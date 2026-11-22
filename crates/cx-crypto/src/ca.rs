use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("tls config error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("invalid dns name: {0}")]
    InvalidDnsName(String),
}

/// Process-local ephemeral ECDSA P-256 Root CA used exclusively inside `cx exec`.
/// The CA private key stays strictly in memory on the client machine.
pub struct EphemeralCa {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_pem: String,
    leaf_cache: Cache<String, Arc<ServerConfig>>,
}

impl EphemeralCa {
    pub fn generate() -> Result<Self, CaError> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "cx Local Ephemeral CA");
        dn.push(DnType::OrganizationName, "cx");
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        let ca_cert = params.self_signed(&ca_key)?;
        let ca_pem = ca_cert.pem();

        let leaf_cache = Cache::builder()
            .max_capacity(512)
            .time_to_live(Duration::from_secs(3600))
            .build();

        Ok(Self {
            ca_cert,
            ca_key,
            ca_pem,
            leaf_cache,
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// Build a merged CA bundle PEM containing all OS system root CAs + this ephemeral CA.
    pub fn build_merged_system_ca_bundle(&self) -> String {
        let mut bundle = String::new();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                cert.as_ref(),
            );
            bundle.push_str("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                if let Ok(line) = std::str::from_utf8(chunk) {
                    bundle.push_str(line);
                    bundle.push('\n');
                }
            }
            bundle.push_str("-----END CERTIFICATE-----\n");
        }
        bundle.push_str(&self.ca_pem);
        bundle
    }

    /// Return (or generate and cache) a `rustls::ServerConfig` with a leaf cert for `host`.
    pub fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(cfg) = self.leaf_cache.get(&key) {
            return Ok(cfg);
        }

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, key.clone());
        params.distinguished_name = dn;
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        if let Ok(ip) = key.parse::<std::net::IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        } else {
            let dns = key
                .clone()
                .try_into()
                .map_err(|_| CaError::InvalidDnsName(key.clone()))?;
            params.subject_alt_names = vec![SanType::DnsName(dns)];
        }

        let leaf_cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        let cert_chain = vec![leaf_cert.der().clone(), self.ca_cert.der().clone()];
        let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key)?;
        tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let arc = Arc::new(tls_cfg);
        self.leaf_cache.insert(key, arc.clone());
        Ok(arc)
    }

    /// Generate a self-signed certificate pair for local development / testing (e.g. `cx-server`).
    pub fn generate_dev_server_cert(sans: &[&str]) -> Result<(String, String), CaError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(
            sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )?;
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let cert = params.self_signed(&key)?;
        Ok((cert.pem(), key.serialize_pem()))
    }
}
