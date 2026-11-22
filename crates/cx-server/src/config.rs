use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cx_crypto::VirtualKeySpec;
use cx_plugin::{PolicyRuleConfig, ProfileSpec, SecretBinding};
use cx_protocol::DefaultRouteAction;
use serde::{Deserialize, Serialize};

/// Clean infrastructure-focused server config (`server.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFileConfig {
    pub http: HttpConfig,
    pub quic: QuicConfig,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub dirs: DirsConfig,
    /// Optional static bootstrap users (for local dev, CI, or initial admin setup).
    #[serde(default)]
    pub bootstrap_users: Vec<BootstrapUserConfig>,
    /// Optional inline profiles (recommended for small single-file setups or tests;
    /// for production, place one file per profile in `dirs.profiles`).
    #[serde(default)]
    pub profiles: Vec<ProfileFileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_http_listen")]
    pub listen: String,
    pub external_url: String,
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

fn default_http_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1/32".into(), "::1/128".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    #[serde(default = "default_quic_listen")]
    pub listen: String,
    pub public_addr: String,
    #[serde(default)]
    pub server_name: Option<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
    #[serde(default = "default_cert_reload")]
    pub cert_reload_secs: u64,
    #[serde(default = "default_keep_alive")]
    pub keep_alive_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub max_idle_timeout_secs: u64,
    #[serde(default = "default_bidi_streams")]
    pub max_concurrent_bidi_streams: u32,
}

fn default_quic_listen() -> String {
    "0.0.0.0:8443".into()
}
fn default_cert_reload() -> u64 {
    300
}
fn default_keep_alive() -> u64 {
    15
}
fn default_idle_timeout() -> u64 {
    60
}
fn default_bidi_streams() -> u32 {
    256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub client_secret_inline: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub admin_groups: Vec<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec![
        "openid".into(),
        "profile".into(),
        "email".into(),
        "groups".into(),
    ]
}
fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub postgres: PostgresConfig,
    #[serde(default = "default_master_key_env")]
    pub master_key_env: String,
    #[serde(default)]
    pub master_key_inline: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            postgres: PostgresConfig::default(),
            master_key_env: default_master_key_env(),
            master_key_inline: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    Disable,
    Allow,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    #[serde(default = "default_pg_host")]
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    #[serde(default = "default_pg_database")]
    pub database: String,
    #[serde(default = "default_pg_username")]
    pub username: String,
    #[serde(default = "default_pg_password_env")]
    pub password_env: String,
    /// Optional inline password (local dev / testing only; prefer `password_env` in production).
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub ssl_mode: PostgresSslMode,
    #[serde(default = "default_pg_max_conns")]
    pub max_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            host: default_pg_host(),
            port: default_pg_port(),
            database: default_pg_database(),
            username: default_pg_username(),
            password_env: default_pg_password_env(),
            password: None,
            ssl_mode: PostgresSslMode::Prefer,
            max_connections: default_pg_max_conns(),
        }
    }
}

impl PostgresConfig {
    pub fn resolve_password(&self) -> Option<String> {
        self.password
            .clone()
            .or_else(|| std::env::var(&self.password_env).ok())
    }
}

fn default_pg_host() -> String {
    "127.0.0.1".into()
}
fn default_pg_port() -> u16 {
    5432
}
fn default_pg_database() -> String {
    "cx".into()
}
fn default_pg_username() -> String {
    "cx".into()
}
fn default_pg_password_env() -> String {
    "CX_POSTGRES_PASSWORD".into()
}
fn default_pg_max_conns() -> u32 {
    16
}
fn default_master_key_env() -> String {
    "CX_MASTER_KEY".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_true")]
    pub block_private_ips: bool,
    #[serde(default)]
    pub allow_private_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// Optional host -> "ip:port" dial overrides (for automated tests).
    #[serde(default)]
    pub upstream_overrides: BTreeMap<String, String>,
    /// Optional extra CA PEM trusted when dialing upstreams.
    #[serde(default)]
    pub extra_upstream_ca_pem: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            block_private_ips: true,
            allow_private_cidrs: vec![],
            allow_private_targets: false,
            session_ttl_secs: 900,
            upstream_overrides: BTreeMap::new(),
            extra_upstream_ca_pem: None,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_session_ttl() -> u64 {
    900
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirsConfig {
    #[serde(default)]
    pub providers: Option<PathBuf>,
    #[serde(default)]
    pub profiles: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub enable_builtin_providers: bool,
}

impl Default for DirsConfig {
    fn default() -> Self {
        Self {
            providers: None,
            profiles: None,
            enable_builtin_providers: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapUserConfig {
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_env: Option<String>,
}

/// One profile per file in `profiles/<name>.toml` (or inline under `[[profiles]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileFileConfig {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    /// Strongly-typed secret source bindings configured under `[secrets.<field>]`.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretBinding>,
    /// Optional profile-level override for `[virtual_key]` generation rules.
    #[serde(default)]
    pub virtual_key: Option<VirtualKeySpec>,
    #[serde(default)]
    pub allow: ProfileAllowConfig,
    #[serde(default)]
    pub routing: ProfileRoutingOverride,
    #[serde(default)]
    pub policy: ProfilePolicyConfig,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePolicyConfig {
    #[serde(default)]
    pub preset: Option<String>,
    /// Structured L7 policy rules (`[[policy.rules]]`).
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAllowConfig {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRoutingOverride {
    #[serde(default)]
    pub inject_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub passthrough_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub passthrough_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub fallback: Option<DefaultRouteAction>,
}

impl ProfileFileConfig {
    pub fn to_profile_spec(&self) -> ProfileSpec {
        ProfileSpec {
            name: self.name.clone(),
            provider_id: self.provider.clone(),
            params: self.params.clone(),
            secrets: self.secrets.clone(),
            virtual_key_override: self.virtual_key.clone(),
            preset: self.policy.preset.clone(),
            rules: self.policy.rules.clone(),
            override_inject_hosts: self.routing.inject_hosts.clone(),
            override_passthrough_hosts: self.routing.passthrough_hosts.clone(),
            override_passthrough_ports: self.routing.passthrough_ports.clone(),
            deny_hosts: self.routing.deny_hosts.clone(),
            fallback: self.routing.fallback,
            allowed_groups: self.allow.groups.clone(),
            allowed_users: self.allow.users.clone(),
            allow_insecure_http: self.allow_insecure_http,
        }
    }
}

impl ServerFileConfig {
    /// Load `server.toml`, resolving relative `dirs.*` / `quic.*` / `storage.*` paths
    /// against the directory containing `server.toml`, and loading all `profiles/*.toml`.
    pub fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        let raw = fs::read_to_string(path)?;
        let mut cfg: Self = toml::from_str(&raw)?;

        // Resolve relative file/dir paths relative to config file directory
        cfg.quic.cert = resolve_rel(base_dir, &cfg.quic.cert);
        cfg.quic.key = resolve_rel(base_dir, &cfg.quic.key);
        if let Some(p) = &cfg.dirs.providers {
            cfg.dirs.providers = Some(resolve_rel(base_dir, p));
        }
        if let Some(p) = &cfg.dirs.profiles {
            let dir = resolve_rel(base_dir, p);
            if dir.exists() {
                let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?
                    .filter_map(|e| e.ok().map(|de| de.path()))
                    .filter(|f| f.extension().and_then(|e| e.to_str()) == Some("toml"))
                    .collect();
                entries.sort();
                for file in entries {
                    let content = fs::read_to_string(&file)?;
                    let prof: ProfileFileConfig = toml::from_str(&content).map_err(|e| {
                        anyhow::anyhow!("failed parsing profile {}: {e}", file.display())
                    })?;
                    cfg.profiles.push(prof);
                }
            }
            cfg.dirs.profiles = Some(dir);
        }

        Ok(cfg)
    }

    pub fn quic_server_name(&self) -> String {
        if let Some(sni) = &self.quic.server_name {
            return sni.clone();
        }
        self.quic
            .public_addr
            .rsplit_once(':')
            .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').to_string())
            .unwrap_or_else(|| self.quic.public_addr.clone())
    }
}

fn resolve_rel(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}
