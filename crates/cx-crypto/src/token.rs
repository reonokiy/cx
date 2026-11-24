use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("malformed session token")]
    Malformed,
    #[error("invalid session token signature")]
    InvalidSignature,
    #[error("session token expired")]
    Expired,
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sid: String,
    pub uid: String,
    pub email: String,
    pub groups: Vec<String>,
    pub profile: String,
    /// Map of `platform_id -> SHA-256 hex digest` of each platform's ephemeral virtual key.
    #[serde(default)]
    pub vk_hashes: BTreeMap<String, String>,
    /// Verified client IP captured at the L7 control plane.
    pub client_ip: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct SessionSigner {
    signing_key: SigningKey,
}

#[derive(Clone)]
pub struct SessionVerifier {
    verifying_key: VerifyingKey,
}

impl SessionSigner {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn verifier(&self) -> SessionVerifier {
        SessionVerifier {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    pub fn sign(&self, claims: &SessionClaims) -> Result<String, TokenError> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"CXS"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

impl SessionVerifier {
    pub fn verify(&self, token: &str) -> Result<SessionClaims, TokenError> {
        let mut parts = token.split('.');
        let header = parts.next().ok_or(TokenError::Malformed)?;
        let payload = parts.next().ok_or(TokenError::Malformed)?;
        let sig_b64 = parts.next().ok_or(TokenError::Malformed)?;
        if parts.next().is_some() {
            return Err(TokenError::Malformed);
        }

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| TokenError::Malformed)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::InvalidSignature)?;
        let signing_input = format!("{header}.{payload}");
        self.verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| TokenError::InvalidSignature)?;

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TokenError::Malformed)?;
        let claims: SessionClaims = serde_json::from_slice(&payload_bytes)?;
        if Utc::now().timestamp() > claims.exp {
            return Err(TokenError::Expired);
        }
        Ok(claims)
    }
}
