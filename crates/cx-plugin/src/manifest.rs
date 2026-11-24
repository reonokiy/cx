use std::collections::BTreeMap;

use cx_crypto::VirtualKeySpec;
use cx_protocol::DefaultRouteAction;
use serde::{Deserialize, Serialize};

pub const BUILTIN_GITHUB_TOML: &str = include_str!("../../../providers/github.toml");
pub const BUILTIN_OPENAI_TOML: &str = include_str!("../../../providers/openai.toml");
pub const BUILTIN_GENERIC_HTTP_TOML: &str = include_str!("../../../providers/generic-http.toml");

/// Clean declarative service provider manifest (`providers/<id>.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub id: String,
    /// Human-readable display name distinct from machine `id` (defaults to `id` when omitted).
    #[serde(default)]
    pub name: Option<String>,
    /// Optional icon identifier (e.g. `"github"`, `"openai"`, `"globe"`), emoji, or `data:image/...` URI.
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub description: String,
    /// Dedicated section controlling how virtual placeholder keys are generated.
    #[serde(default)]
    pub virtual_key: VirtualKeySpec,
    /// Parameter definitions: either a bare default string (`api_host = "api.github.com"`)
    /// or `{ required = true }` / `{ default = "..." }`.
    #[serde(default)]
    pub params: BTreeMap<String, ParamSpec>,
    /// Environment variables injected into client `cx exec` subprocesses.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional declarative Git SSH->HTTPS rewrite rules for the client.
    #[serde(default)]
    pub git: Vec<GitRuleTemplate>,
    /// Tier 1 credential injection rules. Their hosts are automatically aggregated
    /// as the provider's Tier 1 `inject_hosts` (single source of truth).
    #[serde(default)]
    pub inject: Vec<InjectRuleConfig>,
    /// Tier 2 server-side L4 passthrough (no TLS MITM, zero secret injection).
    #[serde(default)]
    pub passthrough: PassthroughTemplate,
    /// Optional Tier 2b L7 audited HTTP passthrough hosts (zero secret injection).
    #[serde(default)]
    pub http_passthrough_hosts: Vec<String>,
    /// Default Tier 3 fallback action when a host matches neither inject nor passthrough.
    #[serde(default)]
    pub fallback: DefaultRouteAction,
    /// Structured policy presets (`[[presets.readonly]]`, `[[presets.full]]`).
    #[serde(default)]
    pub presets: BTreeMap<String, Vec<PolicyRuleConfig>>,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

impl ProviderManifest {
    /// Resolved UI display name (falls back to `id` when `name` is omitted or blank).
    pub fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParamSpec {
    Default(String),
    Detailed {
        #[serde(default)]
        required: bool,
        #[serde(default)]
        default: Option<String>,
    },
}

impl ParamSpec {
    pub fn default_value(&self) -> Option<&str> {
        match self {
            Self::Default(s) => Some(s.as_str()),
            Self::Detailed { default, .. } => default.as_deref(),
        }
    }

    pub fn is_required(&self) -> bool {
        match self {
            Self::Default(_) => false,
            Self::Detailed { required, default } => *required && default.is_none(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassthroughTemplate {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "default_https_ports")]
    pub ports: Vec<u16>,
}

fn default_https_ports() -> Vec<u16> {
    vec![443]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRuleTemplate {
    pub host: String,
    #[serde(default)]
    pub rewrite_from: Vec<String>,
    #[serde(default = "default_git_user")]
    pub username: String,
}

fn default_git_user() -> String {
    "x-access-token".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectMode {
    Bearer,
    Basic,
    Header,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectRuleConfig {
    #[serde(default)]
    pub id: String,
    pub hosts: Vec<String>,
    #[serde(default = "default_https_schemes")]
    pub schemes: Vec<String>,
    pub mode: InjectMode,
    /// Target header name (defaults to `Authorization`).
    #[serde(default = "default_auth_header")]
    pub header: String,
    /// Accepted incoming schemes for `mode = "bearer"` (defaults to `["Bearer"]`).
    #[serde(default = "default_bearer_accept")]
    pub accept_schemes: Vec<String>,
    /// Outgoing scheme prefix for `bearer` / `header` (empty string injects bare token).
    #[serde(default)]
    pub inject_scheme: Option<String>,
    /// Username injected for `mode = "basic"`.
    #[serde(default = "default_git_user")]
    pub username: String,
    /// Optional expected incoming username for `mode = "basic"`.
    #[serde(default)]
    pub expected_username: Option<String>,
    /// Secret field key referenced in Profile's `[secret]` section (e.g. `token`, `api_key`).
    pub secret: String,
}

fn default_https_schemes() -> Vec<String> {
    vec!["https".into()]
}

fn default_auth_header() -> String {
    "Authorization".into()
}

fn default_bearer_accept() -> Vec<String> {
    vec!["Bearer".into()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleConfig {
    pub effect: PolicyEffect,
    #[serde(default = "default_wildcard_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "default_wildcard_paths")]
    pub paths: Vec<String>,
}

fn default_wildcard_methods() -> Vec<String> {
    vec!["*".into()]
}

fn default_wildcard_paths() -> Vec<String> {
    vec!["/**".into()]
}

/// Interpolate both short `{{key}}` and legacy `{{params.key}}` placeholders.
pub fn render_params(template: &str, params: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in params {
        out = out.replace(&format!("{{{{params.{k}}}}}"), v);
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

/// Interpolate `{{virtual_key}}` plus parameter placeholders.
pub fn render_client_template(
    template: &str,
    params: &BTreeMap<String, String>,
    virtual_key: &str,
) -> String {
    render_params(template, params).replace("{{virtual_key}}", virtual_key)
}
