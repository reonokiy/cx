use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine;
use cx_crypto::{constant_time_eq_str, hash_secret_hex};
use cx_protocol::host_matches_pattern;
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

pub type ResolvedSecretMap = BTreeMap<String, SecretString>;

/// Strictly header/metadata-only HTTP request view exposed to `AuthInjector`.
/// The HTTP body is intentionally omitted so injectors can NEVER perform unsafe global body replacement.
#[derive(Debug, Clone)]
pub struct UpstreamHttpRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: Vec<(String, Vec<u8>)>,
}

pub struct InjectionContext<'a> {
    /// Allowed virtual key SHA-256 hex digests for this session (ephemeral key + optional static keys).
    pub allowed_vk_hashes: &'a [String],
}

impl<'a> InjectionContext<'a> {
    pub fn matches_virtual_key(&self, presented: &str) -> bool {
        let candidate_hash = hash_secret_hex(presented);
        self.allowed_vk_hashes
            .iter()
            .any(|expected| constant_time_eq_str(&candidate_hash, expected))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionOutcome {
    Injected,
    NoMatchingCredentialPresented,
}

#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("missing required secret field '{0}'")]
    MissingSecretField(String),
    #[error("invalid virtual key presented for host '{0}'")]
    InvalidVirtualKey(String),
    #[error("malformed authorization header")]
    MalformedHeader,
}

#[async_trait]
pub trait AuthInjector: Send + Sync {
    fn id(&self) -> &str;
    fn allowed_hosts(&self) -> &[String];
    fn allowed_schemes(&self) -> &[String];

    fn matches_target(&self, host: &str, scheme: &str) -> bool {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        let scheme_lc = scheme.to_ascii_lowercase();
        self.allowed_schemes()
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&scheme_lc))
            && self
                .allowed_hosts()
                .iter()
                .any(|p| host_matches_pattern(&host_lc, p))
    }

    async fn inject(
        &self,
        req: &mut UpstreamHttpRequest,
        ctx: &InjectionContext<'_>,
        secret: &ResolvedSecretMap,
    ) -> Result<InjectionOutcome, InjectionError>;
}

/// Replaces `Authorization: <Bearer|token> <virtual_key>` with `<inject_scheme> <real_secret>`.
pub struct BearerHeaderInjector {
    pub id: String,
    pub hosts: Vec<String>,
    pub schemes: Vec<String>,
    pub header: String,
    pub match_schemes: Vec<String>,
    pub inject_scheme: String,
    pub secret_field: String,
}

#[async_trait]
impl AuthInjector for BearerHeaderInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn allowed_hosts(&self) -> &[String] {
        &self.hosts
    }

    fn allowed_schemes(&self) -> &[String] {
        &self.schemes
    }

    async fn inject(
        &self,
        req: &mut UpstreamHttpRequest,
        ctx: &InjectionContext<'_>,
        secret: &ResolvedSecretMap,
    ) -> Result<InjectionOutcome, InjectionError> {
        let Some(real_val) = secret.get(&self.secret_field) else {
            return Err(InjectionError::MissingSecretField(self.secret_field.clone()));
        };

        let mut injected = false;
        for (name, val) in &mut req.headers {
            if !name.eq_ignore_ascii_case(&self.header) {
                continue;
            }
            let Ok(val_str) = std::str::from_utf8(val) else {
                return Err(InjectionError::MalformedHeader);
            };
            let trimmed = val_str.trim();
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let scheme = parts.next().unwrap_or("");
            let presented = parts.next().map(str::trim).unwrap_or("");

            if !self
                .match_schemes
                .iter()
                .any(|s| s.eq_ignore_ascii_case(scheme))
            {
                continue;
            }

            if !ctx.matches_virtual_key(presented) {
                return Err(InjectionError::InvalidVirtualKey(req.host.clone()));
            }

            let new_val = if self.inject_scheme.is_empty() {
                real_val.expose_secret().to_string()
            } else {
                format!("{} {}", self.inject_scheme, real_val.expose_secret())
            };
            *val = new_val.into_bytes();
            injected = true;
        }

        if injected {
            Ok(InjectionOutcome::Injected)
        } else {
            Ok(InjectionOutcome::NoMatchingCredentialPresented)
        }
    }
}

/// Replaces HTTP Basic Auth password (used by `git` over HTTPS) when it matches the virtual key.
pub struct BasicAuthInjector {
    pub id: String,
    pub hosts: Vec<String>,
    pub schemes: Vec<String>,
    pub expected_username: Option<String>,
    pub inject_username: String,
    pub password_field: String,
}

#[async_trait]
impl AuthInjector for BasicAuthInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn allowed_hosts(&self) -> &[String] {
        &self.hosts
    }

    fn allowed_schemes(&self) -> &[String] {
        &self.schemes
    }

    async fn inject(
        &self,
        req: &mut UpstreamHttpRequest,
        ctx: &InjectionContext<'_>,
        secret: &ResolvedSecretMap,
    ) -> Result<InjectionOutcome, InjectionError> {
        let Some(real_val) = secret.get(&self.password_field) else {
            return Err(InjectionError::MissingSecretField(
                self.password_field.clone(),
            ));
        };

        let mut injected = false;
        for (name, val) in &mut req.headers {
            if !name.eq_ignore_ascii_case("authorization") {
                continue;
            }
            let Ok(val_str) = std::str::from_utf8(val) else {
                return Err(InjectionError::MalformedHeader);
            };
            let trimmed = val_str.trim();
            let Some(rest) = trimmed
                .strip_prefix("Basic ")
                .or_else(|| trimmed.strip_prefix("basic "))
            else {
                continue;
            };
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(rest.trim())
                .map_err(|_| InjectionError::MalformedHeader)?;
            let decoded_str =
                String::from_utf8(decoded).map_err(|_| InjectionError::MalformedHeader)?;
            let (user, pass) = decoded_str
                .split_once(':')
                .ok_or(InjectionError::MalformedHeader)?;

            if let Some(expected_u) = &self.expected_username {
                if user != expected_u {
                    return Err(InjectionError::InvalidVirtualKey(req.host.clone()));
                }
            }
            // Git may place the token in password (with `x-access-token`) or username when password is empty.
            let matched = ctx.matches_virtual_key(pass)
                || (pass.is_empty() && ctx.matches_virtual_key(user));
            if !matched {
                return Err(InjectionError::InvalidVirtualKey(req.host.clone()));
            }

            let raw_pair = format!("{}:{}", self.inject_username, real_val.expose_secret());
            let encoded = base64::engine::general_purpose::STANDARD.encode(raw_pair.as_bytes());
            *val = format!("Basic {encoded}").into_bytes();
            injected = true;
        }

        if injected {
            Ok(InjectionOutcome::Injected)
        } else {
            Ok(InjectionOutcome::NoMatchingCredentialPresented)
        }
    }
}

/// Replaces raw or scheme-prefixed token in an arbitrary header (e.g. `X-API-Key: <vk>`).
pub struct HeaderTokenInjector {
    pub id: String,
    pub hosts: Vec<String>,
    pub schemes: Vec<String>,
    pub header: String,
    pub inject_scheme: String,
    pub secret_field: String,
}

#[async_trait]
impl AuthInjector for HeaderTokenInjector {
    fn id(&self) -> &str {
        &self.id
    }

    fn allowed_hosts(&self) -> &[String] {
        &self.hosts
    }

    fn allowed_schemes(&self) -> &[String] {
        &self.schemes
    }

    async fn inject(
        &self,
        req: &mut UpstreamHttpRequest,
        ctx: &InjectionContext<'_>,
        secret: &ResolvedSecretMap,
    ) -> Result<InjectionOutcome, InjectionError> {
        let Some(real_val) = secret.get(&self.secret_field) else {
            return Err(InjectionError::MissingSecretField(self.secret_field.clone()));
        };

        let mut injected = false;
        for (name, val) in &mut req.headers {
            if !name.eq_ignore_ascii_case(&self.header) {
                continue;
            }
            let Ok(val_str) = std::str::from_utf8(val) else {
                return Err(InjectionError::MalformedHeader);
            };
            let trimmed = val_str.trim();
            let presented = if !self.inject_scheme.is_empty() {
                let mut parts = trimmed.splitn(2, char::is_whitespace);
                let first = parts.next().unwrap_or("");
                if first.eq_ignore_ascii_case(&self.inject_scheme) {
                    parts.next().map(str::trim).unwrap_or("")
                } else {
                    trimmed
                }
            } else {
                trimmed
            };

            if !ctx.matches_virtual_key(presented) {
                return Err(InjectionError::InvalidVirtualKey(req.host.clone()));
            }

            let new_val = if self.inject_scheme.is_empty() {
                real_val.expose_secret().to_string()
            } else {
                format!("{} {}", self.inject_scheme, real_val.expose_secret())
            };
            *val = new_val.into_bytes();
            injected = true;
        }

        if injected {
            Ok(InjectionOutcome::Injected)
        } else {
            Ok(InjectionOutcome::NoMatchingCredentialPresented)
        }
    }
}
