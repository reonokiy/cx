use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use cx_crypto::{EncryptedSecretBlob, EnvelopeCipher, hash_secret_hex};
use secrecy::SecretString;
use serde::Serialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::config::{PostgresConfig, PostgresSslMode};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("postgres error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] cx_crypto::envelope::CryptoError),
    #[error("database secret encryption is not configured (set CX_MASTER_KEY or [security].master_key_env)")]
    MasterKeyNotConfigured,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub oidc_issuer: String,
    pub oidc_subject: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct AuthPrincipal {
    pub user: UserRecord,
    /// Optional profile restriction when authenticated via a scoped PAT.
    pub allowed_profiles: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct CliLoginRecord {
    pub login_id: String,
    pub user_code: String,
    pub poll_secret_hash: String,
    pub oidc_state: String,
    pub oidc_nonce: String,
    pub pkce_verifier: String,
    pub status: String,
    pub approved_token: Option<String>,
    pub approved_user_id: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub occurred_at: i64,
    pub user_id: String,
    pub user_email: String,
    pub session_id: String,
    pub profile_name: String,
    pub route_tier: String,
    pub target_host: String,
    pub target_port: u16,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub status_code: Option<u16>,
    pub decision: String,
    pub deny_reason: Option<String>,
    pub client_ip: String,
    pub latency_ms: u64,
}

#[async_trait]
pub trait ServerStore: Send + Sync {
    async fn upsert_user(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        display_name: &str,
        groups: &[String],
    ) -> Result<UserRecord, StoreError>;

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>, StoreError>;

    async fn insert_access_token(
        &self,
        user_id: &str,
        name: &str,
        raw_token: &str,
        allowed_profiles: Option<&[String]>,
        expires_at: i64,
    ) -> Result<String, StoreError>;

    async fn verify_access_token(&self, raw_token: &str) -> Result<Option<AuthPrincipal>, StoreError>;

    async fn create_cli_login(&self, rec: &CliLoginRecord) -> Result<(), StoreError>;
    async fn get_cli_login_by_code(&self, user_code: &str) -> Result<Option<CliLoginRecord>, StoreError>;
    async fn get_cli_login_by_state(&self, oidc_state: &str) -> Result<Option<CliLoginRecord>, StoreError>;
    async fn get_cli_login_by_id(&self, login_id: &str) -> Result<Option<CliLoginRecord>, StoreError>;
    async fn approve_cli_login(
        &self,
        login_id: &str,
        user_id: &str,
        issued_access_token: &str,
    ) -> Result<(), StoreError>;
    async fn consume_cli_login(&self, login_id: &str) -> Result<(), StoreError>;

    async fn create_virtual_key(
        &self,
        owner_user_id: &str,
        profile_name: &str,
        raw_vk: &str,
        expires_at: Option<i64>,
    ) -> Result<String, StoreError>;

    async fn list_active_virtual_key_hashes(
        &self,
        owner_user_id: &str,
        profile_name: &str,
    ) -> Result<Vec<String>, StoreError>;

    fn has_master_key(&self) -> bool;

    async fn upsert_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
        fields: &BTreeMap<String, String>,
    ) -> Result<(), StoreError>;

    async fn get_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
    ) -> Result<Option<BTreeMap<String, SecretString>>, StoreError>;

    async fn revoke_session(&self, session_id: &str) -> Result<(), StoreError>;
    async fn is_session_revoked(&self, session_id: &str) -> Result<bool, StoreError>;

    async fn record_audit(&self, ev: &AuditEvent) -> Result<(), StoreError>;
    async fn count_audit_logs(&self) -> Result<i64, StoreError>;
}

// ============================ POSTGRESQL STORE ============================

pub struct PostgresStore {
    pool: PgPool,
    cipher: Option<EnvelopeCipher>,
}

impl PostgresStore {
    pub async fn connect(
        pg: &PostgresConfig,
        cipher: Option<EnvelopeCipher>,
    ) -> Result<Self, StoreError> {
        let ssl_mode = match pg.ssl_mode {
            PostgresSslMode::Disable => PgSslMode::Disable,
            PostgresSslMode::Allow => PgSslMode::Allow,
            PostgresSslMode::Prefer => PgSslMode::Prefer,
            PostgresSslMode::Require => PgSslMode::Require,
            PostgresSslMode::VerifyCa => PgSslMode::VerifyCa,
            PostgresSslMode::VerifyFull => PgSslMode::VerifyFull,
        };

        let mut opts = PgConnectOptions::new()
            .host(&pg.host)
            .port(pg.port)
            .database(&pg.database)
            .username(&pg.username)
            .ssl_mode(ssl_mode);

        if let Some(pwd) = pg.resolve_password() {
            opts = opts.password(&pwd);
        }

        let pool = PgPoolOptions::new()
            .max_connections(pg.max_connections)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool, cipher })
    }

    async fn query_cli_login(&self, sql: &str, val: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        let row = sqlx::query(sql)
            .bind(val)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| CliLoginRecord {
            login_id: r.get("login_id"),
            user_code: r.get("user_code"),
            poll_secret_hash: r.get("poll_secret_hash"),
            oidc_state: r.get("oidc_state"),
            oidc_nonce: r.get("oidc_nonce"),
            pkce_verifier: r.get("pkce_verifier"),
            status: r.get("status"),
            approved_token: r.get("approved_token"),
            approved_user_id: r.get("approved_user_id"),
            expires_at: r.get("expires_at"),
        }))
    }
}

#[async_trait]
impl ServerStore for PostgresStore {
    async fn upsert_user(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        display_name: &str,
        groups: &[String],
    ) -> Result<UserRecord, StoreError> {
        let now = Utc::now().timestamp();
        let new_id = Uuid::new_v4().to_string();
        let groups_vec = groups.to_vec();

        let row = sqlx::query(
            r#"
            INSERT INTO users (id, oidc_issuer, oidc_subject, email, display_name, groups, status, created_at, last_login_at)
            VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $7)
            ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET
                email = EXCLUDED.email,
                display_name = EXCLUDED.display_name,
                groups = EXCLUDED.groups,
                last_login_at = EXCLUDED.last_login_at
            RETURNING id, status
            "#,
        )
        .bind(&new_id)
        .bind(issuer)
        .bind(subject)
        .bind(email)
        .bind(display_name)
        .bind(Json(&groups_vec))
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(UserRecord {
            id: row.get("id"),
            oidc_issuer: issuer.to_string(),
            oidc_subject: subject.to_string(),
            email: email.to_string(),
            display_name: display_name.to_string(),
            groups: groups_vec,
            status: row.get("status"),
        })
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, oidc_issuer, oidc_subject, email, display_name, groups, status FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let groups: Json<Vec<String>> = r.get("groups");
            UserRecord {
                id: r.get("id"),
                oidc_issuer: r.get("oidc_issuer"),
                oidc_subject: r.get("oidc_subject"),
                email: r.get("email"),
                display_name: r.get("display_name"),
                groups: groups.0,
                status: r.get("status"),
            }
        }))
    }

    async fn insert_access_token(
        &self,
        user_id: &str,
        name: &str,
        raw_token: &str,
        allowed_profiles: Option<&[String]>,
        expires_at: i64,
    ) -> Result<String, StoreError> {
        let id = Uuid::new_v4().to_string();
        let token_hash = hash_secret_hex(raw_token);
        let profiles = allowed_profiles.map(|s| Json(s.to_vec()));
        let now = Utc::now().timestamp();

        let row = sqlx::query(
            r#"
            INSERT INTO access_tokens (id, user_id, name, token_hash, allowed_profiles, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (token_hash) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                name = EXCLUDED.name,
                allowed_profiles = EXCLUDED.allowed_profiles,
                expires_at = EXCLUDED.expires_at,
                revoked_at = NULL
            RETURNING id
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(name)
        .bind(&token_hash)
        .bind(profiles)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("id"))
    }

    async fn verify_access_token(&self, raw_token: &str) -> Result<Option<AuthPrincipal>, StoreError> {
        let token_hash = hash_secret_hex(raw_token);
        let now = Utc::now().timestamp();

        let row = sqlx::query(
            r#"
            SELECT t.allowed_profiles, t.expires_at, t.revoked_at,
                   u.id, u.oidc_issuer, u.oidc_subject, u.email, u.display_name, u.groups, u.status
            FROM access_tokens t
            JOIN users u ON u.id = t.user_id
            WHERE t.token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(None);
        };
        let revoked_at: Option<i64> = r.get("revoked_at");
        let expires_at: i64 = r.get("expires_at");
        let status: String = r.get("status");
        if revoked_at.is_some() || now > expires_at || status != "active" {
            return Ok(None);
        }

        let groups: Json<Vec<String>> = r.get("groups");
        let allowed_profiles: Option<Json<Vec<String>>> = r.get("allowed_profiles");
        Ok(Some(AuthPrincipal {
            user: UserRecord {
                id: r.get("id"),
                oidc_issuer: r.get("oidc_issuer"),
                oidc_subject: r.get("oidc_subject"),
                email: r.get("email"),
                display_name: r.get("display_name"),
                groups: groups.0,
                status,
            },
            allowed_profiles: allowed_profiles.map(|j| j.0),
        }))
    }

    async fn create_cli_login(&self, rec: &CliLoginRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO cli_logins (login_id, user_code, poll_secret_hash, oidc_state, oidc_nonce, pkce_verifier, status, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&rec.login_id)
        .bind(&rec.user_code)
        .bind(&rec.poll_secret_hash)
        .bind(&rec.oidc_state)
        .bind(&rec.oidc_nonce)
        .bind(&rec.pkce_verifier)
        .bind(&rec.status)
        .bind(rec.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_cli_login_by_code(&self, user_code: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        self.query_cli_login(
            "SELECT login_id, user_code, poll_secret_hash, oidc_state, oidc_nonce, pkce_verifier, status, approved_token, approved_user_id, expires_at FROM cli_logins WHERE user_code = $1",
            user_code,
        )
        .await
    }

    async fn get_cli_login_by_state(&self, oidc_state: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        self.query_cli_login(
            "SELECT login_id, user_code, poll_secret_hash, oidc_state, oidc_nonce, pkce_verifier, status, approved_token, approved_user_id, expires_at FROM cli_logins WHERE oidc_state = $1",
            oidc_state,
        )
        .await
    }

    async fn get_cli_login_by_id(&self, login_id: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        self.query_cli_login(
            "SELECT login_id, user_code, poll_secret_hash, oidc_state, oidc_nonce, pkce_verifier, status, approved_token, approved_user_id, expires_at FROM cli_logins WHERE login_id = $1",
            login_id,
        )
        .await
    }

    async fn approve_cli_login(
        &self,
        login_id: &str,
        user_id: &str,
        issued_access_token: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE cli_logins SET status = 'approved', approved_user_id = $1, approved_token = $2 WHERE login_id = $3",
        )
        .bind(user_id)
        .bind(issued_access_token)
        .bind(login_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consume_cli_login(&self, login_id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE cli_logins SET status = 'consumed', approved_token = NULL WHERE login_id = $1")
            .bind(login_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn create_virtual_key(
        &self,
        owner_user_id: &str,
        profile_name: &str,
        raw_vk: &str,
        expires_at: Option<i64>,
    ) -> Result<String, StoreError> {
        let id = Uuid::new_v4().to_string();
        let key_hash = hash_secret_hex(raw_vk);
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            INSERT INTO virtual_keys (id, key_hash, owner_user_id, profile_name, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&id)
        .bind(&key_hash)
        .bind(owner_user_id)
        .bind(profile_name)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn list_active_virtual_key_hashes(
        &self,
        owner_user_id: &str,
        profile_name: &str,
    ) -> Result<Vec<String>, StoreError> {
        let now = Utc::now().timestamp();
        let rows = sqlx::query(
            r#"
            SELECT key_hash FROM virtual_keys
            WHERE owner_user_id = $1 AND profile_name = $2
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > $3)
            "#,
        )
        .bind(owner_user_id)
        .bind(profile_name)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.get("key_hash")).collect())
    }

    fn has_master_key(&self) -> bool {
        self.cipher.is_some()
    }

    async fn upsert_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
        fields: &BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(StoreError::MasterKeyNotConfigured)?;
        let json = serde_json::to_string(fields)?;
        let blob = cipher.encrypt_secret(&SecretString::from(json))?;
        let now = Utc::now().timestamp();

        sqlx::query(
            r#"
            INSERT INTO secrets (name, scope, owner_user_id, blob, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (name, scope, owner_user_id) DO UPDATE SET
                blob = EXCLUDED.blob,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(name)
        .bind(scope)
        .bind(owner_user_id.unwrap_or(""))
        .bind(Json(blob))
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
    ) -> Result<Option<BTreeMap<String, SecretString>>, StoreError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(StoreError::MasterKeyNotConfigured)?;
        let row = sqlx::query(
            "SELECT blob FROM secrets WHERE name = $1 AND scope = $2 AND owner_user_id = $3",
        )
        .bind(name)
        .bind(scope)
        .bind(owner_user_id.unwrap_or(""))
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(None);
        };
        let blob: Json<EncryptedSecretBlob> = r.get("blob");
        let pt = cipher.decrypt_secret(&blob.0)?;
        let raw_map: BTreeMap<String, String> =
            serde_json::from_str(secrecy::ExposeSecret::expose_secret(&pt))?;
        Ok(Some(
            raw_map
                .into_iter()
                .map(|(k, v)| (k, SecretString::from(v)))
                .collect(),
        ))
    }

    async fn revoke_session(&self, session_id: &str) -> Result<(), StoreError> {
        let now = Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO revoked_sessions (session_id, revoked_at) VALUES ($1, $2) ON CONFLICT (session_id) DO NOTHING",
        )
        .bind(session_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn is_session_revoked(&self, session_id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT 1 FROM revoked_sessions WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn record_audit(&self, ev: &AuditEvent) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                occurred_at, user_id, user_email, session_id, profile_name,
                route_tier, target_host, target_port, http_method, http_path,
                status_code, decision, deny_reason, client_ip, latency_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            "#,
        )
        .bind(ev.occurred_at)
        .bind(&ev.user_id)
        .bind(&ev.user_email)
        .bind(&ev.session_id)
        .bind(&ev.profile_name)
        .bind(&ev.route_tier)
        .bind(&ev.target_host)
        .bind(ev.target_port as i32)
        .bind(&ev.http_method)
        .bind(&ev.http_path)
        .bind(ev.status_code.map(|c| c as i32))
        .bind(&ev.decision)
        .bind(&ev.deny_reason)
        .bind(&ev.client_ip)
        .bind(ev.latency_ms as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn count_audit_logs(&self) -> Result<i64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS cnt FROM audit_logs")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("cnt"))
    }
}

// ============================ IN-MEMORY STORE (FOR UNIT/OFFLINE TESTS ONLY) ============================

#[derive(Default)]
struct MemInner {
    users: HashMap<String, UserRecord>,
    oidc_index: HashMap<(String, String), String>,
    tokens: HashMap<String, (String, Option<Vec<String>>, i64, Option<i64>)>,
    cli_logins: HashMap<String, CliLoginRecord>,
    virtual_keys: Vec<(String, String, String, Option<i64>)>, // (key_hash, owner_uid, profile, exp)
    secrets: HashMap<(String, String, String), EncryptedSecretBlob>,
    revoked_sessions: HashSet<String>,
    audits: Vec<AuditEvent>,
}

/// Pure in-memory store strictly for unit/offline tests when a PostgreSQL daemon isn't running.
/// Production `cx-server serve` always uses `PostgresStore`.
pub struct MemoryStore {
    inner: Mutex<MemInner>,
    cipher: Option<EnvelopeCipher>,
}

impl MemoryStore {
    pub fn new(cipher: Option<EnvelopeCipher>) -> Self {
        Self {
            inner: Mutex::new(MemInner::default()),
            cipher,
        }
    }
}

#[async_trait]
impl ServerStore for MemoryStore {
    async fn upsert_user(
        &self,
        issuer: &str,
        subject: &str,
        email: &str,
        display_name: &str,
        groups: &[String],
    ) -> Result<UserRecord, StoreError> {
        let mut st = self.inner.lock().unwrap();
        let key = (issuer.to_string(), subject.to_string());
        let id = st
            .oidc_index
            .entry(key)
            .or_insert_with(|| Uuid::new_v4().to_string())
            .clone();
        let status = st
            .users
            .get(&id)
            .map(|u| u.status.clone())
            .unwrap_or_else(|| "active".to_string());
        let rec = UserRecord {
            id: id.clone(),
            oidc_issuer: issuer.to_string(),
            oidc_subject: subject.to_string(),
            email: email.to_string(),
            display_name: display_name.to_string(),
            groups: groups.to_vec(),
            status,
        };
        st.users.insert(id, rec.clone());
        Ok(rec)
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>, StoreError> {
        Ok(self.inner.lock().unwrap().users.get(user_id).cloned())
    }

    async fn insert_access_token(
        &self,
        user_id: &str,
        _name: &str,
        raw_token: &str,
        allowed_profiles: Option<&[String]>,
        expires_at: i64,
    ) -> Result<String, StoreError> {
        let mut st = self.inner.lock().unwrap();
        let id = Uuid::new_v4().to_string();
        st.tokens.insert(
            hash_secret_hex(raw_token),
            (
                user_id.to_string(),
                allowed_profiles.map(|s| s.to_vec()),
                expires_at,
                None,
            ),
        );
        Ok(id)
    }

    async fn verify_access_token(&self, raw_token: &str) -> Result<Option<AuthPrincipal>, StoreError> {
        let st = self.inner.lock().unwrap();
        let now = Utc::now().timestamp();
        let Some((uid, profiles, exp, revoked)) = st.tokens.get(&hash_secret_hex(raw_token)) else {
            return Ok(None);
        };
        if revoked.is_some() || now > *exp {
            return Ok(None);
        }
        let Some(user) = st.users.get(uid).cloned() else {
            return Ok(None);
        };
        if user.status != "active" {
            return Ok(None);
        }
        Ok(Some(AuthPrincipal {
            user,
            allowed_profiles: profiles.clone(),
        }))
    }

    async fn create_cli_login(&self, rec: &CliLoginRecord) -> Result<(), StoreError> {
        self.inner
            .lock()
            .unwrap()
            .cli_logins
            .insert(rec.login_id.clone(), rec.clone());
        Ok(())
    }

    async fn get_cli_login_by_code(&self, user_code: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .cli_logins
            .values()
            .find(|r| r.user_code == user_code)
            .cloned())
    }

    async fn get_cli_login_by_state(&self, oidc_state: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .cli_logins
            .values()
            .find(|r| r.oidc_state == oidc_state)
            .cloned())
    }

    async fn get_cli_login_by_id(&self, login_id: &str) -> Result<Option<CliLoginRecord>, StoreError> {
        Ok(self.inner.lock().unwrap().cli_logins.get(login_id).cloned())
    }

    async fn approve_cli_login(
        &self,
        login_id: &str,
        user_id: &str,
        issued_access_token: &str,
    ) -> Result<(), StoreError> {
        if let Some(rec) = self.inner.lock().unwrap().cli_logins.get_mut(login_id) {
            rec.status = "approved".into();
            rec.approved_user_id = Some(user_id.into());
            rec.approved_token = Some(issued_access_token.into());
        }
        Ok(())
    }

    async fn consume_cli_login(&self, login_id: &str) -> Result<(), StoreError> {
        if let Some(rec) = self.inner.lock().unwrap().cli_logins.get_mut(login_id) {
            rec.status = "consumed".into();
            rec.approved_token = None;
        }
        Ok(())
    }

    async fn create_virtual_key(
        &self,
        owner_user_id: &str,
        profile_name: &str,
        raw_vk: &str,
        expires_at: Option<i64>,
    ) -> Result<String, StoreError> {
        self.inner.lock().unwrap().virtual_keys.push((
            hash_secret_hex(raw_vk),
            owner_user_id.into(),
            profile_name.into(),
            expires_at,
        ));
        Ok(Uuid::new_v4().to_string())
    }

    async fn list_active_virtual_key_hashes(
        &self,
        owner_user_id: &str,
        profile_name: &str,
    ) -> Result<Vec<String>, StoreError> {
        let now = Utc::now().timestamp();
        Ok(self
            .inner
            .lock()
            .unwrap()
            .virtual_keys
            .iter()
            .filter(|(_, u, p, exp)| {
                u == owner_user_id && p == profile_name && exp.map(|e| e > now).unwrap_or(true)
            })
            .map(|(h, _, _, _)| h.clone())
            .collect())
    }

    fn has_master_key(&self) -> bool {
        self.cipher.is_some()
    }

    async fn upsert_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
        fields: &BTreeMap<String, String>,
    ) -> Result<(), StoreError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(StoreError::MasterKeyNotConfigured)?;
        let json = serde_json::to_string(fields)?;
        let blob = cipher.encrypt_secret(&SecretString::from(json))?;
        self.inner.lock().unwrap().secrets.insert(
            (
                name.into(),
                scope.into(),
                owner_user_id.unwrap_or("").into(),
            ),
            blob,
        );
        Ok(())
    }

    async fn get_encrypted_secret(
        &self,
        name: &str,
        scope: &str,
        owner_user_id: Option<&str>,
    ) -> Result<Option<BTreeMap<String, SecretString>>, StoreError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(StoreError::MasterKeyNotConfigured)?;
        let blob = self
            .inner
            .lock()
            .unwrap()
            .secrets
            .get(&(
                name.into(),
                scope.into(),
                owner_user_id.unwrap_or("").into(),
            ))
            .cloned();
        let Some(blob) = blob else {
            return Ok(None);
        };
        let pt = cipher.decrypt_secret(&blob)?;
        let raw_map: BTreeMap<String, String> =
            serde_json::from_str(secrecy::ExposeSecret::expose_secret(&pt))?;
        Ok(Some(
            raw_map
                .into_iter()
                .map(|(k, v)| (k, SecretString::from(v)))
                .collect(),
        ))
    }

    async fn revoke_session(&self, session_id: &str) -> Result<(), StoreError> {
        self.inner
            .lock()
            .unwrap()
            .revoked_sessions
            .insert(session_id.into());
        Ok(())
    }

    async fn is_session_revoked(&self, session_id: &str) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .revoked_sessions
            .contains(session_id))
    }

    async fn record_audit(&self, ev: &AuditEvent) -> Result<(), StoreError> {
        self.inner.lock().unwrap().audits.push(ev.clone());
        Ok(())
    }

    async fn count_audit_logs(&self) -> Result<i64, StoreError> {
        Ok(self.inner.lock().unwrap().audits.len() as i64)
    }
}
