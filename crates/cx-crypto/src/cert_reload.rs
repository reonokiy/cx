use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum CertLoadError {
    #[error("failed to read certificate or key file: {0}")]
    Io(#[from] std::io::Error),
    #[error("no certificates found in PEM file")]
    NoCerts,
    #[error("no private key found in PEM file")]
    NoKey,
    #[error("unsupported or invalid private key: {0}")]
    InvalidKey(String),
}

/// TLS certificate resolver supporting zero-downtime hot reload (including Let's Encrypt symlinks).
#[derive(Debug)]
pub struct HotReloadCertResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: ArcSwap<CertifiedKey>,
    last_digest: std::sync::Mutex<[u8; 32]>,
}

impl HotReloadCertResolver {
    pub fn from_pem_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Arc<Self>, CertLoadError> {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        let (certified_key, digest) = load_certified_key(&cert_path, &key_path)?;
        Ok(Arc::new(Self {
            cert_path,
            key_path,
            current: ArcSwap::from_pointee(certified_key),
            last_digest: std::sync::Mutex::new(digest),
        }))
    }

    /// Reload certificate if file contents changed. Safe against atomic symlink swaps.
    pub fn reload_if_changed(&self) -> Result<bool, CertLoadError> {
        let cert_bytes = fs::read(&self.cert_path)?;
        let key_bytes = fs::read(&self.key_path)?;
        let digest = compute_digest(&cert_bytes, &key_bytes);

        {
            let guard = self.last_digest.lock().unwrap();
            if *guard == digest {
                return Ok(false);
            }
        }

        let certified_key = parse_certified_key(&cert_bytes, &key_bytes)?;
        self.current.store(Arc::new(certified_key));
        *self.last_digest.lock().unwrap() = digest;
        info!(cert = %self.cert_path.display(), "hot-reloaded QUIC TLS certificate");
        Ok(true)
    }

    /// Spawn a background watcher polling the certificate files periodically.
    pub fn spawn_reload_watcher(self: &Arc<Self>, interval: Duration) {
        let this = Arc::clone(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            if let Err(err) = this.reload_if_changed() {
                warn!(error = %err, "failed to hot-reload QUIC TLS certificate; keeping previous cert");
            }
        });
    }
}

impl ResolvesServerCert for HotReloadCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

fn compute_digest(cert_bytes: &[u8], key_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_bytes);
    hasher.update(b"\0");
    hasher.update(key_bytes);
    hasher.finalize().into()
}

fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(CertifiedKey, [u8; 32]), CertLoadError> {
    let cert_bytes = fs::read(cert_path)?;
    let key_bytes = fs::read(key_path)?;
    let digest = compute_digest(&cert_bytes, &key_bytes);
    let ck = parse_certified_key(&cert_bytes, &key_bytes)?;
    Ok((ck, digest))
}

fn parse_certified_key(
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<CertifiedKey, CertLoadError> {
    let mut cert_reader = BufReader::new(cert_bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(CertLoadError::NoCerts);
    }

    let mut key_reader = BufReader::new(key_bytes);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or(CertLoadError::NoKey)?;

    let signing_key =
        any_supported_type(&key).map_err(|e| CertLoadError::InvalidKey(e.to_string()))?;
    Ok(CertifiedKey::new(certs, signing_key))
}
