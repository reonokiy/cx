use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const LOWER_ALNUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const UPPER_ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX_LOWER: &[u8] = b"0123456789abcdef";
const HEX_UPPER: &[u8] = b"0123456789ABCDEF";

pub const MIN_VK_RANDOM_LENGTH: usize = 16;
pub const MAX_VK_RANDOM_LENGTH: usize = 256;

#[derive(Debug, Error)]
pub enum VirtualKeySpecError {
    #[error(
        "virtual_key.length={0} is out of allowed range ({MIN_VK_RANDOM_LENGTH}..={MAX_VK_RANDOM_LENGTH})"
    )]
    InvalidLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VirtualKeyFormat {
    #[default]
    Random,
    Hex,
    Base64url,
    Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VirtualKeyCharset {
    #[default]
    Alnum,
    LowerAlnum,
    UpperAlnum,
    HexLower,
    HexUpper,
}

/// Declarative specification controlling how virtual placeholder keys are generated
/// to match upstream CLI local token format validations (e.g., `gho_`, `sk-`, `AKIA...`, UUID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualKeySpec {
    #[serde(default)]
    pub format: VirtualKeyFormat,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
    #[serde(default = "default_length")]
    pub length: usize,
    #[serde(default)]
    pub charset: VirtualKeyCharset,
}

fn default_prefix() -> String {
    "cx_vk_".to_string()
}

fn default_length() -> usize {
    32
}

impl Default for VirtualKeySpec {
    fn default() -> Self {
        Self {
            format: VirtualKeyFormat::Random,
            prefix: default_prefix(),
            suffix: String::new(),
            length: default_length(),
            charset: VirtualKeyCharset::Alnum,
        }
    }
}

impl VirtualKeySpec {
    pub fn validate(&self) -> Result<(), VirtualKeySpecError> {
        if self.format != VirtualKeyFormat::Uuid
            && !(MIN_VK_RANDOM_LENGTH..=MAX_VK_RANDOM_LENGTH).contains(&self.length)
        {
            return Err(VirtualKeySpecError::InvalidLength(self.length));
        }
        Ok(())
    }

    pub fn generate(&self) -> String {
        let body = match self.format {
            VirtualKeyFormat::Uuid => Uuid::new_v4().to_string(),
            VirtualKeyFormat::Hex => generate_from_alphabet(HEX_LOWER, self.length),
            VirtualKeyFormat::Base64url => {
                let raw_bytes_len = (self.length * 3).div_ceil(4) + 2;
                let mut raw = vec![0u8; raw_bytes_len];
                rand::thread_rng().fill_bytes(&mut raw);
                let mut encoded = URL_SAFE_NO_PAD.encode(raw);
                encoded.truncate(self.length);
                encoded
            }
            VirtualKeyFormat::Random => {
                let alphabet = match self.charset {
                    VirtualKeyCharset::Alnum => ALNUM,
                    VirtualKeyCharset::LowerAlnum => LOWER_ALNUM,
                    VirtualKeyCharset::UpperAlnum => UPPER_ALNUM,
                    VirtualKeyCharset::HexLower => HEX_LOWER,
                    VirtualKeyCharset::HexUpper => HEX_UPPER,
                };
                generate_from_alphabet(alphabet, self.length)
            }
        };
        format!("{}{}{}", self.prefix, body, self.suffix)
    }
}

fn generate_from_alphabet(alphabet: &[u8], count: usize) -> String {
    let mut bytes = vec![0u8; count];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(count);
    for b in bytes {
        out.push(alphabet[(b as usize) % alphabet.len()] as char);
    }
    out
}

/// Generate a high-entropy URL-safe alphanumeric token with a prefix.
pub fn generate_random_token(prefix: &str, rand_chars: usize) -> String {
    format!("{prefix}{}", generate_from_alphabet(ALNUM, rand_chars))
}

pub fn hash_secret_hex(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    ha.as_slice().ct_eq(hb.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EphemeralCa, EnvelopeCipher, SessionClaims, SessionSigner};
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn virtual_key_spec_formats_and_guardrails() {
        let gh = VirtualKeySpec {
            format: VirtualKeyFormat::Random,
            prefix: "gho_cx_".into(),
            suffix: String::new(),
            length: 32,
            charset: VirtualKeyCharset::Alnum,
        };
        assert!(gh.validate().is_ok());
        let k = gh.generate();
        assert!(k.starts_with("gho_cx_"));
        assert_eq!(k.len(), "gho_cx_".len() + 32);

        let aws = VirtualKeySpec {
            format: VirtualKeyFormat::Random,
            prefix: "AKIACX".into(),
            suffix: String::new(),
            length: 16,
            charset: VirtualKeyCharset::UpperAlnum,
        };
        let ak = aws.generate();
        assert!(ak.starts_with("AKIACX"));
        assert!(ak[6..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));

        let uuid_spec = VirtualKeySpec {
            format: VirtualKeyFormat::Uuid,
            prefix: "cx-".into(),
            suffix: "-v1".into(),
            length: 0,
            charset: VirtualKeyCharset::Alnum,
        };
        assert!(uuid_spec.validate().is_ok());
        let uk = uuid_spec.generate();
        assert!(uk.starts_with("cx-") && uk.ends_with("-v1"));
        assert_eq!(uk.len(), 3 + 36 + 3);

        let weak = VirtualKeySpec {
            length: 8,
            ..Default::default()
        };
        assert!(weak.validate().is_err());
    }

    #[test]
    fn envelope_roundtrip() {
        let (cipher, _b64) = EnvelopeCipher::generate_random();
        let secret = SecretString::from("ghp_super_secret_token_12345".to_string());
        let blob = cipher.encrypt_secret(&secret).unwrap();
        let decrypted = cipher.decrypt_secret(&blob).unwrap();
        assert_eq!(decrypted.expose_secret(), "ghp_super_secret_token_12345");
    }

    #[test]
    fn session_token_sign_and_verify() {
        let signer = SessionSigner::generate();
        let verifier = signer.verifier();
        let claims = SessionClaims {
            sid: "sess_1".into(),
            uid: "user_1".into(),
            email: "alice@example.com".into(),
            groups: vec!["eng".into()],
            profile: "github-ro".into(),
            vk_hash: hash_secret_hex("gho_cx_test"),
            client_ip: "203.0.113.5".into(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 300,
        };
        let jwt = signer.sign(&claims).unwrap();
        let parsed = verifier.verify(&jwt).unwrap();
        assert_eq!(parsed.email, "alice@example.com");
        assert_eq!(parsed.client_ip, "203.0.113.5");
    }

    #[test]
    fn ephemeral_ca_generates_leaf() {
        let ca = EphemeralCa::generate().unwrap();
        let cfg1 = ca.server_config_for_host("api.github.com").unwrap();
        let cfg2 = ca.server_config_for_host("API.GITHUB.COM.").unwrap();
        assert!(std::sync::Arc::ptr_eq(&cfg1, &cfg2));
    }
}
