use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::config::OidcConfig;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("http error calling OIDC provider: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OIDC token exchange failed: {0}")]
    TokenExchange(String),
    #[error("OIDC ID token verification failed: {0}")]
    Jwt(String),
    #[error("missing OIDC claim: {0}")]
    MissingClaim(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedOidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub groups: Vec<String>,
}

pub struct OidcClient {
    config: OidcConfig,
    redirect_uri: String,
    http: reqwest::Client,
    discovery: RwLock<Option<DiscoveryDoc>>,
    jwks: RwLock<Option<JwkSet>>,
}

impl OidcClient {
    pub fn new(config: OidcConfig, external_url: &str) -> Arc<Self> {
        let redirect_uri = format!(
            "{}/v1/auth/oidc/callback",
            external_url.trim_end_matches('/')
        );
        Arc::new(Self {
            config,
            redirect_uri,
            http: reqwest::Client::new(),
            discovery: RwLock::new(None),
            jwks: RwLock::new(None),
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    pub async fn discovery(&self) -> Result<DiscoveryDoc, OidcError> {
        if let Some(doc) = self.discovery.read().await.clone() {
            return Ok(doc);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let doc: DiscoveryDoc = self.http.get(url).send().await?.error_for_status()?.json().await?;
        *self.discovery.write().await = Some(doc.clone());
        Ok(doc)
    }

    async fn get_jwks(&self, force_refresh: bool) -> Result<JwkSet, OidcError> {
        if !force_refresh {
            if let Some(set) = self.jwks.read().await.clone() {
                return Ok(set);
            }
        }
        let doc = self.discovery().await?;
        let set: JwkSet = self
            .http
            .get(&doc.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        *self.jwks.write().await = Some(set.clone());
        Ok(set)
    }

    pub async fn build_authorize_url(
        &self,
        state: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<String, OidcError> {
        let doc = self.discovery().await?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let scope = self.config.scopes.join(" ");

        let mut url = reqwest::Url::parse(&doc.authorization_endpoint)
            .map_err(|e| OidcError::TokenExchange(e.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &scope)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(url.to_string())
    }

    pub async fn exchange_and_verify(
        &self,
        code: &str,
        pkce_verifier: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedOidcIdentity, OidcError> {
        let doc = self.discovery().await?;
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("client_id", self.config.client_id.clone()),
            ("code_verifier", pkce_verifier.into()),
        ];

        let client_secret = self
            .config
            .client_secret_inline
            .clone()
            .or_else(|| {
                self.config
                    .client_secret_env
                    .as_deref()
                    .and_then(|k| std::env::var(k).ok())
            });
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }

        let resp = self.http.post(&doc.token_endpoint).form(&form).send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(OidcError::TokenExchange(text));
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
            #[serde(default)]
            access_token: Option<String>,
        }
        let tok: TokenResponse = resp.json().await?;
        let mut identity = self
            .verify_id_token(&tok.id_token, &doc.issuer, expected_nonce)
            .await?;

        if identity.avatar_url.is_none() {
            if let (Some(endpoint), Some(access_token)) =
                (doc.userinfo_endpoint.as_deref(), tok.access_token.as_deref())
            {
                if let Some(picture) = self.fetch_userinfo_picture(endpoint, access_token).await {
                    identity.avatar_url = Some(picture);
                }
            }
        }

        Ok(identity)
    }

    async fn fetch_userinfo_picture(&self, endpoint: &str, access_token: &str) -> Option<String> {
        let resp = self
            .http
            .get(endpoint)
            .bearer_auth(access_token)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: Value = resp.json().await.ok()?;
        body.get("picture")
            .and_then(|v| v.as_str())
            .and_then(sanitize_avatar_url)
    }

    async fn verify_id_token(
        &self,
        id_token: &str,
        expected_issuer: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedOidcIdentity, OidcError> {
        let header =
            decode_header(id_token).map_err(|e| OidcError::Jwt(format!("header: {e}")))?;
        let kid = header.kid.as_deref();

        let mut jwks = self.get_jwks(false).await?;
        let jwk = match find_jwk(&jwks, kid) {
            Some(j) => j.clone(),
            None => {
                jwks = self.get_jwks(true).await?;
                find_jwk(&jwks, kid)
                    .ok_or_else(|| OidcError::Jwt("matching JWK not found".into()))?
                    .clone()
            }
        };

        let decoding_key =
            DecodingKey::from_jwk(&jwk).map_err(|e| OidcError::Jwt(format!("jwk: {e}")))?;

        let alg = match header.alg {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 | Algorithm::ES384 => header.alg,
            other => return Err(OidcError::Jwt(format!("unsupported alg: {other:?}"))),
        };

        let mut validation = Validation::new(alg);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[expected_issuer]);

        let token_data = decode::<Value>(id_token, &decoding_key, &validation)
            .map_err(|e| OidcError::Jwt(e.to_string()))?;
        let claims = token_data.claims;

        let nonce = claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if nonce != expected_nonce {
            return Err(OidcError::Jwt("nonce mismatch".into()));
        }

        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcError::MissingClaim("sub".into()))?
            .to_string();
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or(&subject)
            .to_string();
        let display_name = claims
            .get("name")
            .or_else(|| claims.get("preferred_username"))
            .and_then(|v| v.as_str())
            .unwrap_or(&email)
            .to_string();

        let avatar_url = claims
            .get("picture")
            .and_then(|v| v.as_str())
            .and_then(sanitize_avatar_url);

        let groups = extract_dot_path_string_array(&claims, &self.config.groups_claim);

        Ok(VerifiedOidcIdentity {
            issuer: expected_issuer.to_string(),
            subject,
            email,
            display_name,
            avatar_url,
            groups,
        })
    }
}

pub fn sanitize_avatar_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 2048 {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let parsed = reqwest::Url::parse(trimmed).ok()?;
    match parsed.scheme() {
        "https" => Some(trimmed.to_string()),
        "http" => match parsed.host_str() {
            Some("localhost" | "127.0.0.1" | "::1") => Some(trimmed.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn find_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>) -> Option<&'a jsonwebtoken::jwk::Jwk> {
    if let Some(k) = kid {
        jwks.find(k)
    } else {
        jwks.keys.first()
    }
}

/// Extract string array from a possibly nested claim path like `"groups"` or `"realm_access.roles"`.
pub fn extract_dot_path_string_array(claims: &Value, path: &str) -> Vec<String> {
    let mut cur = claims;
    for seg in path.split('.') {
        match cur.get(seg) {
            Some(next) => cur = next,
            None => return vec![],
        }
    }
    match cur {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(ToString::to_string))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_avatar_url;

    #[test]
    fn sanitizes_oidc_avatar_urls() {
        assert_eq!(
            sanitize_avatar_url("https://id.nokiy.net/api/users/123/profile-picture.png").as_deref(),
            Some("https://id.nokiy.net/api/users/123/profile-picture.png")
        );
        assert_eq!(
            sanitize_avatar_url("http://127.0.0.1:5556/avatar.png").as_deref(),
            Some("http://127.0.0.1:5556/avatar.png")
        );
        assert!(sanitize_avatar_url("http://evil.example.com/avatar.png").is_none());
        assert!(sanitize_avatar_url("javascript:alert(1)").is_none());
        assert!(sanitize_avatar_url("data:image/svg+xml,<svg/>").is_none());
        assert!(sanitize_avatar_url("https://id.nokiy.net/a b").is_none());
    }
}
