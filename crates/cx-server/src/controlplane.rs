use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use cx_crypto::{
    SessionClaims, SessionSigner, constant_time_eq_str, generate_random_token, hash_secret_hex,
};
use cx_plugin::ResolvedProfile;
use cx_protocol::{
    CliLoginPollRequest, CliLoginPollResponse, CliLoginStartResponse, CreateScopedTokenRequest,
    CreateScopedTokenResponse, CreateSessionRequest, CreateSessionResponse,
    CreateVirtualKeyRequest, CreateVirtualKeyResponse, ProfileSummary, UpsertSecretRequest,
    UserSummary,
};
use ipnet::IpNet;
use serde::Deserialize;
use uuid::Uuid;

use crate::oidc::OidcClient;
use crate::store::{AuthPrincipal, CliLoginRecord, ServerStore, UserRecord};

pub struct ControlPlaneState {
    pub external_url: String,
    pub quic_public_addr: String,
    pub quic_server_name: String,
    pub session_ttl_secs: u64,
    pub trusted_proxies: Vec<IpNet>,
    pub admin_groups: Vec<String>,
    pub signer: SessionSigner,
    pub store: Arc<dyn ServerStore>,
    pub oidc: Option<Arc<OidcClient>>,
    pub profiles: Arc<BTreeMap<String, Arc<ResolvedProfile>>>,
}

pub fn build_router(state: Arc<ControlPlaneState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/cli/start", post(cli_login_start))
        .route("/auth/cli", get(cli_login_browser_start))
        .route("/v1/auth/oidc/callback", get(oidc_callback))
        .route("/v1/auth/cli/poll", post(cli_login_poll))
        .route("/v1/whoami", get(whoami))
        .route("/v1/profiles", get(list_profiles))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/{id}", delete(revoke_session))
        .route("/v1/tokens", post(create_scoped_token))
        .route("/v1/virtual-keys", post(create_virtual_key))
        .route("/v1/secrets", post(upsert_secret))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

fn extract_client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> String {
    let peer_trusted = trusted_proxies.iter().any(|net| net.contains(&peer.ip()));
    if peer_trusted {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next().map(str::trim) {
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = real_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    peer.ip().to_string()
}

async fn authenticate_request(
    state: &ControlPlaneState,
    headers: &HeaderMap,
) -> Result<AuthPrincipal, (StatusCode, String)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing Authorization header".into()))?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(str::trim)
        .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer token".into()))?;

    state
        .store
        .verify_access_token(token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "invalid or expired token".into()))
}

fn to_user_summary(u: &UserRecord) -> UserSummary {
    UserSummary {
        id: u.id.clone(),
        email: u.email.clone(),
        display_name: u.display_name.clone(),
        groups: u.groups.clone(),
    }
}

// --- OIDC Server-Relayed CLI Login ---

async fn cli_login_start(
    State(state): State<Arc<ControlPlaneState>>,
) -> Result<Json<CliLoginStartResponse>, (StatusCode, String)> {
    if state.oidc.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "OIDC is not configured on this server; use `cx login --token <pat>`".into(),
        ));
    }
    let login_id = Uuid::new_v4().to_string();
    let user_code = format!(
        "{}-{}",
        generate_random_token("", 4).to_ascii_uppercase(),
        generate_random_token("", 4).to_ascii_uppercase()
    );
    let poll_secret = generate_random_token("cxpoll_", 32);
    let oidc_state = generate_random_token("cxst_", 24);
    let oidc_nonce = generate_random_token("cxnc_", 24);
    let pkce_verifier = generate_random_token("", 48);
    let expires_in_secs = 300u64;
    let expires_at = Utc::now().timestamp() + expires_in_secs as i64;

    state
        .store
        .create_cli_login(&CliLoginRecord {
            login_id: login_id.clone(),
            user_code: user_code.clone(),
            poll_secret_hash: hash_secret_hex(&poll_secret),
            oidc_state,
            oidc_nonce,
            pkce_verifier,
            status: "pending".into(),
            approved_token: None,
            approved_user_id: None,
            expires_at,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verification_url = format!(
        "{}/auth/cli?code={}",
        state.external_url.trim_end_matches('/'),
        user_code
    );

    Ok(Json(CliLoginStartResponse {
        login_id,
        user_code,
        poll_secret,
        verification_url,
        expires_in_secs,
    }))
}

#[derive(Deserialize)]
struct BrowserLoginQuery {
    code: String,
}

async fn cli_login_browser_start(
    State(state): State<Arc<ControlPlaneState>>,
    Query(q): Query<BrowserLoginQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "OIDC not configured".into()))?;
    let rec = state
        .store
        .get_cli_login_by_code(&q.code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "invalid login code".into()))?;

    if rec.status != "pending" || Utc::now().timestamp() > rec.expires_at {
        return Err((StatusCode::GONE, "login code expired or already used".into()));
    }

    let auth_url = oidc
        .build_authorize_url(&rec.oidc_state, &rec.oidc_nonce, &rec.pkce_verifier)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("OIDC error: {e}")))?;

    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<Arc<ControlPlaneState>>,
    Query(q): Query<OidcCallbackQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "OIDC not configured".into()))?;

    let rec = state
        .store
        .get_cli_login_by_state(&q.state)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::BAD_REQUEST, "unknown OIDC state".into()))?;

    if rec.status != "pending" || Utc::now().timestamp() > rec.expires_at {
        return Err((StatusCode::GONE, "login session expired".into()));
    }

    let identity = oidc
        .exchange_and_verify(&q.code, &rec.pkce_verifier, &rec.oidc_nonce)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("OIDC verification failed: {e}")))?;

    let user = state
        .store
        .upsert_user(
            &identity.issuer,
            &identity.subject,
            &identity.email,
            &identity.display_name,
            &identity.groups,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw_access_token = generate_random_token("cx_at_", 40);
    let token_exp = Utc::now().timestamp() + 7 * 24 * 3600;
    state
        .store
        .insert_access_token(&user.id, "oidc-cli-login", &raw_access_token, None, token_exp)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .approve_cli_login(&rec.login_id, &user.id, &raw_access_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(format!(
        "<html><body><h2>cx login succeeded</h2><p>Signed in as <b>{}</b>. You may close this tab and return to your terminal.</p></body></html>",
        user.email
    )))
}

async fn cli_login_poll(
    State(state): State<Arc<ControlPlaneState>>,
    Json(req): Json<CliLoginPollRequest>,
) -> Result<Json<CliLoginPollResponse>, (StatusCode, String)> {
    let rec = state
        .store
        .get_cli_login_by_id(&req.login_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "unknown login_id".into()))?;

    if !constant_time_eq_str(&hash_secret_hex(&req.poll_secret), &rec.poll_secret_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid poll_secret".into()));
    }

    if Utc::now().timestamp() > rec.expires_at && rec.status == "pending" {
        return Ok(Json(CliLoginPollResponse {
            status: "expired".into(),
            access_token: None,
            user: None,
        }));
    }

    if rec.status == "approved" {
        let user = match rec.approved_user_id.as_deref() {
            Some(uid) => state
                .store
                .get_user_by_id(uid)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| to_user_summary(&u)),
            None => None,
        };
        let _ = state.store.consume_cli_login(&rec.login_id).await;
        return Ok(Json(CliLoginPollResponse {
            status: "approved".into(),
            access_token: rec.approved_token,
            user,
        }));
    }

    Ok(Json(CliLoginPollResponse {
        status: rec.status,
        access_token: None,
        user: None,
    }))
}

// --- Identity, Profiles, Sessions & Keys ---

async fn whoami(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Json<UserSummary>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    Ok(Json(to_user_summary(&principal.user)))
}

async fn list_profiles(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileSummary>>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let list = state
        .profiles
        .values()
        .filter(|p| {
            let group_ok = p.user_has_access(
                &principal.user.id,
                &principal.user.email,
                &principal.user.groups,
            );
            let scope_ok = principal
                .allowed_profiles
                .as_ref()
                .map(|allowed| allowed.iter().any(|a| a == &p.name))
                .unwrap_or(true);
            group_ok && scope_ok
        })
        .map(|p| ProfileSummary {
            name: p.name.clone(),
            plugin_id: p.provider_id.clone(),
            inject_hosts: p.routing.inject_hosts.clone(),
            server_tunnel_hosts: p.routing.server_tunnel_hosts.clone(),
            default_action: p.routing.default_action,
        })
        .collect();
    Ok(Json(list))
}

async fn create_session(
    State(state): State<Arc<ControlPlaneState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let profile = state
        .profiles
        .get(&req.profile)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("profile '{}' not found", req.profile),
        ))?;

    if !profile.user_has_access(
        &principal.user.id,
        &principal.user.email,
        &principal.user.groups,
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("user lacks RBAC access to profile '{}'", req.profile),
        ));
    }
    if let Some(allowed) = &principal.allowed_profiles {
        if !allowed.iter().any(|p| p == &req.profile) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("scoped token cannot access profile '{}'", req.profile),
            ));
        }
    }

    let session_id = format!("sess_{}", Uuid::new_v4().simple());
    let ephemeral_vk = profile.generate_virtual_key();
    let now = Utc::now().timestamp();
    let exp = now + state.session_ttl_secs as i64;
    let client_ip = extract_client_ip(peer, &headers, &state.trusted_proxies);

    let claims = SessionClaims {
        sid: session_id.clone(),
        uid: principal.user.id.clone(),
        email: principal.user.email.clone(),
        groups: principal.user.groups.clone(),
        profile: profile.name.clone(),
        vk_hash: hash_secret_hex(&ephemeral_vk),
        client_ip,
        iat: now,
        exp,
    };

    let session_token = state
        .signer
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let client = profile.build_client_launch_spec(&ephemeral_vk);

    Ok(Json(CreateSessionResponse {
        session_id,
        session_token,
        expires_at: exp,
        quic_endpoint: state.quic_public_addr.clone(),
        quic_server_name: state.quic_server_name.clone(),
        profile: profile.name.clone(),
        routing: profile.routing.clone(),
        client,
    }))
}

async fn revoke_session(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = authenticate_request(&state, &headers).await?;
    state
        .store
        .revoke_session(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_scoped_token(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<CreateScopedTokenRequest>,
) -> Result<Json<CreateScopedTokenResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    for p in &req.profiles {
        let Some(prof) = state.profiles.get(p) else {
            return Err((StatusCode::NOT_FOUND, format!("profile '{p}' not found")));
        };
        if !prof.user_has_access(
            &principal.user.id,
            &principal.user.email,
            &principal.user.groups,
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("cannot grant access to profile '{p}'"),
            ));
        }
    }

    let raw_token = generate_random_token("cx_pat_", 40);
    let ttl = req.ttl_secs.unwrap_or(30 * 24 * 3600);
    let expires_at = Utc::now().timestamp() + ttl as i64;
    let profiles_opt = if req.profiles.is_empty() {
        None
    } else {
        Some(req.profiles.as_slice())
    };
    let id = state
        .store
        .insert_access_token(
            &principal.user.id,
            &req.name,
            &raw_token,
            profiles_opt,
            expires_at,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateScopedTokenResponse {
        id,
        token: raw_token,
        expires_at,
    }))
}

async fn create_virtual_key(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<CreateVirtualKeyRequest>,
) -> Result<Json<CreateVirtualKeyResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let profile = state
        .profiles
        .get(&req.profile)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("profile '{}' not found", req.profile),
        ))?;
    if !profile.user_has_access(
        &principal.user.id,
        &principal.user.email,
        &principal.user.groups,
    ) {
        return Err((StatusCode::FORBIDDEN, "forbidden for this profile".into()));
    }

    let vk = profile.generate_virtual_key();
    let expires_at = req
        .ttl_secs
        .map(|s| Utc::now().timestamp() + s as i64);
    let id = state
        .store
        .create_virtual_key(&principal.user.id, &profile.name, &vk, expires_at)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateVirtualKeyResponse {
        id,
        virtual_key: vk,
        profile: profile.name.clone(),
        expires_at,
    }))
}

async fn upsert_secret(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<UpsertSecretRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let owner = match req.scope.as_str() {
        "shared" => {
            let is_admin = principal
                .user
                .groups
                .iter()
                .any(|g| state.admin_groups.iter().any(|ag| ag == g));
            if !is_admin {
                return Err((
                    StatusCode::FORBIDDEN,
                    "admin group membership required for shared secrets".into(),
                ));
            }
            None
        }
        "personal" => Some(principal.user.id.as_str()),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "scope must be 'shared' or 'personal'".into(),
            ));
        }
    };

    state
        .store
        .upsert_encrypted_secret(&req.name, &req.scope, owner, &req.fields)
        .await
        .map_err(|e| match e {
            crate::store::StoreError::MasterKeyNotConfigured => {
                (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(StatusCode::NO_CONTENT)
}
