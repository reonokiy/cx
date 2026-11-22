use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid master key length (expected 32 bytes base64)")]
    InvalidMasterKey,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecretBlob {
    pub dek_nonce: Vec<u8>,
    pub encrypted_dek: Vec<u8>,
    pub data_nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub key_version: u32,
}

/// AES-256-GCM envelope encryption: each secret gets a fresh random DEK wrapped by the Master KEK.
pub struct EnvelopeCipher {
    kek: [u8; 32],
    key_version: u32,
}

impl Drop for EnvelopeCipher {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

impl EnvelopeCipher {
    pub fn from_base64(b64_key: &str) -> Result<Self, CryptoError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_key.trim())
            .map_err(|_| CryptoError::InvalidMasterKey)?;
        if decoded.len() != 32 {
            return Err(CryptoError::InvalidMasterKey);
        }
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&decoded);
        Ok(Self {
            kek,
            key_version: 1,
        })
    }

    pub fn generate_random() -> (Self, String) {
        let mut kek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kek);
        let b64 = base64::engine::general_purpose::STANDARD.encode(kek);
        (
            Self {
                kek,
                key_version: 1,
            },
            b64,
        )
    }

    pub fn encrypt_secret(&self, plaintext: &SecretString) -> Result<EncryptedSecretBlob, CryptoError> {
        let mut rng = rand::thread_rng();
        let mut dek = [0u8; 32];
        rng.fill_bytes(&mut dek);

        let mut dek_nonce = [0u8; 12];
        rng.fill_bytes(&mut dek_nonce);
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(|_| CryptoError::EncryptFailed)?;
        let encrypted_dek = kek_cipher
            .encrypt(Nonce::from_slice(&dek_nonce), dek.as_ref())
            .map_err(|_| CryptoError::EncryptFailed)?;

        let mut data_nonce = [0u8; 12];
        rng.fill_bytes(&mut data_nonce);
        let dek_cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| CryptoError::EncryptFailed)?;
        let ciphertext = dek_cipher
            .encrypt(Nonce::from_slice(&data_nonce), plaintext.expose_secret().as_bytes())
            .map_err(|_| CryptoError::EncryptFailed)?;

        dek.zeroize();

        Ok(EncryptedSecretBlob {
            dek_nonce: dek_nonce.to_vec(),
            encrypted_dek,
            data_nonce: data_nonce.to_vec(),
            ciphertext,
            key_version: self.key_version,
        })
    }

    pub fn decrypt_secret(&self, blob: &EncryptedSecretBlob) -> Result<SecretString, CryptoError> {
        if blob.dek_nonce.len() != 12 || blob.data_nonce.len() != 12 {
            return Err(CryptoError::DecryptFailed);
        }
        let kek_cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(|_| CryptoError::DecryptFailed)?;
        let mut dek = kek_cipher
            .decrypt(Nonce::from_slice(&blob.dek_nonce), blob.encrypted_dek.as_ref())
            .map_err(|_| CryptoError::DecryptFailed)?;
        if dek.len() != 32 {
            dek.zeroize();
            return Err(CryptoError::DecryptFailed);
        }

        let dek_cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| CryptoError::DecryptFailed)?;
        dek.zeroize();

        let mut pt = dek_cipher
            .decrypt(Nonce::from_slice(&blob.data_nonce), blob.ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptFailed)?;
        let s = String::from_utf8(pt.clone()).map_err(|_| CryptoError::DecryptFailed)?;
        pt.zeroize();
        Ok(SecretString::from(s))
    }
}
