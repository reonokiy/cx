pub mod config;
pub mod controlplane;
pub mod dataplane;
pub mod oidc;
pub mod scrubber;
pub mod ssrf;
pub mod store;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cx_crypto::{EnvelopeCipher, HotReloadCertResolver, SessionSigner};
use cx_plugin::{HostPatternValidator, ProviderRegistry, ResolvedProfile, SecretBinding};
use cx_tunnel::{QuicTuning, QuicTunnelServer};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::ServerFileConfig;
use crate::controlplane::{ControlPlaneState, build_router};
use crate::dataplane::DataPlaneHandler;
use crate::oidc::OidcClient;
use crate::ssrf::SsrfPolicy;
use crate::store::{PostgresStore, ServerStore};

pub struct RunningServer {
    pub http_addr: SocketAddr,
    pub quic_addr: SocketAddr,
    pub store: Arc<dyn ServerStore>,
}

/// Production entrypoint: connects to PostgreSQL, runs migrations, and starts Control + Data planes.
pub async fn start_server(cfg: ServerFileConfig) -> anyhow::Result<RunningServer> {
    let cipher = resolve_cipher(&cfg)?;
    let store: Arc<dyn ServerStore> =
        Arc::new(PostgresStore::connect(&cfg.postgres, cipher).await?);
    start_server_with_store(cfg, store).await
}

/// Start server with an explicit `ServerStore` implementation (used by `start_server` and tests).
pub async fn start_server_with_store(
    cfg: ServerFileConfig,
    store: Arc<dyn ServerStore>,
) -> anyhow::Result<RunningServer> {
    // Seed bootstrap users/tokens if configured
    for bu in &cfg.bootstrap_users {
        let user = store
            .upsert_user(
                "bootstrap",
                &bu.email,
                &bu.email,
                bu.display_name.as_deref().unwrap_or(&bu.email),
                &bu.groups,
            )
            .await?;
        let raw_tok = bu
            .token
            .clone()
            .or_else(|| bu.token_env.as_deref().and_then(|k| std::env::var(k).ok()));
        if let Some(tok) = raw_tok {
            let exp = chrono::Utc::now().timestamp() + 365 * 24 * 3600;
            store
                .insert_access_token(&user.id, "bootstrap", &tok, None, exp)
                .await?;
        }
    }

    // Load provider plugins and resolve profiles
    let validator = HostPatternValidator {
        allow_private_targets: cfg.security.allow_private_targets,
        allow_apex_wildcard: false,
    };
    let registry = ProviderRegistry::new(
        cfg.dirs.providers.clone(),
        cfg.dirs.enable_builtin_providers,
        validator,
    )?;

    let mut resolved_profiles: BTreeMap<String, Arc<ResolvedProfile>> = BTreeMap::new();
    for pcfg in &cfg.profiles {
        let resolved = registry.resolve_profile(&pcfg.to_profile_spec())?;
        if !store.has_master_key() {
            for (field, binding) in &resolved.secret_bindings {
                if matches!(binding, SecretBinding::Db { .. }) {
                    anyhow::bail!(
                        "profile '{}' binds [secrets.{}] to source = \"db\", which requires a 32-byte base64 master key in env '{}' (generate with: openssl rand -base64 32)",
                        resolved.name,
                        field,
                        cfg.security.master_key_env
                    );
                }
            }
        }
        info!(
            profile = %resolved.name,
            provider = %resolved.provider_id,
            inject_hosts = ?resolved.routing.inject_hosts,
            passthrough_hosts = ?resolved.routing.server_tunnel_hosts,
            "loaded profile"
        );
        resolved_profiles.insert(resolved.name.clone(), Arc::new(resolved));
    }
    let profiles = Arc::new(resolved_profiles);

    // Prepare QUIC hot-reloading TLS cert resolver
    let cert_resolver = HotReloadCertResolver::from_pem_files(&cfg.quic.cert, &cfg.quic.key)?;
    if cfg.quic.cert_reload_secs > 0 {
        cert_resolver.spawn_reload_watcher(Duration::from_secs(cfg.quic.cert_reload_secs));
    }

    let tuning = QuicTuning {
        keep_alive_secs: cfg.quic.keep_alive_secs,
        max_idle_timeout_secs: cfg.quic.max_idle_timeout_secs,
        max_concurrent_bidi_streams: cfg.quic.max_concurrent_bidi_streams,
    };
    let quic_listen: SocketAddr = cfg.quic.listen.parse()?;
    let quic_server = QuicTunnelServer::bind(quic_listen, cert_resolver, &tuning)?;
    let quic_addr = quic_server.local_addr()?;

    let signer = SessionSigner::generate();
    let verifier = signer.verifier();

    let allow_cidrs: Vec<IpNet> = cfg
        .security
        .allow_private_cidrs
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;
    let ssrf_policy = Arc::new(SsrfPolicy {
        block_private_ips: cfg.security.block_private_ips,
        allow_cidrs,
        upstream_overrides: cfg.security.upstream_overrides.clone(),
    });
    let upstream_tls =
        DataPlaneHandler::build_upstream_tls(cfg.security.extra_upstream_ca_pem.as_deref())?;

    let dp_handler = Arc::new(DataPlaneHandler {
        verifier,
        store: Arc::clone(&store),
        profiles: Arc::clone(&profiles),
        ssrf_policy,
        upstream_tls,
    });

    tokio::spawn(async move {
        quic_server.serve(dp_handler).await;
    });

    let trusted_proxies: Vec<IpNet> = cfg
        .http
        .trusted_proxies
        .iter()
        .map(|s| s.parse())
        .collect::<Result<_, _>>()?;

    let oidc_client = cfg
        .oidc
        .as_ref()
        .map(|oc| OidcClient::new(oc.clone(), &cfg.http.external_url));

    let admin_groups = cfg
        .oidc
        .as_ref()
        .map(|o| o.admin_groups.clone())
        .unwrap_or_else(|| vec!["cx-admins".into()]);

    let quic_public_addr = if cfg.quic.public_addr.ends_with(":0") {
        let host = cfg
            .quic
            .public_addr
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or("127.0.0.1");
        format!("{host}:{}", quic_addr.port())
    } else {
        cfg.quic.public_addr.clone()
    };

    let cp_state = Arc::new(ControlPlaneState {
        external_url: cfg.http.external_url.clone(),
        quic_public_addr,
        quic_server_name: cfg.quic_server_name(),
        session_ttl_secs: cfg.security.session_ttl_secs,
        trusted_proxies,
        admin_groups,
        signer,
        store: Arc::clone(&store),
        oidc: oidc_client,
        profiles,
    });

    let router = build_router(cp_state);
    let http_listener = TcpListener::bind(&cfg.http.listen).await?;
    let http_addr = http_listener.local_addr()?;
    info!(listen = %http_addr, "HTTP control-plane server bound");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            http_listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!(error = %e, "HTTP control-plane server exited");
        }
    });

    Ok(RunningServer {
        http_addr,
        quic_addr,
        store,
    })
}

/// Resolve optional AES-256-GCM master key (KEK) from `[security].master_key_inline`
/// or `[security].master_key_env` (default `CX_MASTER_KEY`).
/// Returns `Ok(None)` cleanly when unset — only required when using DB-stored secrets (`source = "db"`).
pub fn resolve_cipher(cfg: &ServerFileConfig) -> anyhow::Result<Option<EnvelopeCipher>> {
    if let Some(b64) = &cfg.security.master_key_inline {
        let trimmed = b64.trim();
        if !trimmed.is_empty() {
            return Ok(Some(EnvelopeCipher::from_base64(trimmed)?));
        }
    }
    if let Ok(b64) = std::env::var(&cfg.security.master_key_env) {
        let trimmed = b64.trim();
        if !trimmed.is_empty() {
            return Ok(Some(EnvelopeCipher::from_base64(trimmed)?));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DirsConfig, HttpConfig, PostgresConfig, ProfileAllowConfig, ProfileFileConfig,
        ProfilePolicyConfig, ProfileRoutingOverride, QuicConfig, SecurityConfig,
    };
    use crate::store::MemoryStore;
    use cx_plugin::SecretScope;

    #[tokio::test]
    async fn db_secret_requires_master_key_while_env_secret_does_not() {
        let cfg = ServerFileConfig {
            http: HttpConfig {
                listen: "127.0.0.1:0".into(),
                external_url: "http://127.0.0.1".into(),
                trusted_proxies: vec![],
            },
            quic: QuicConfig {
                listen: "127.0.0.1:0".into(),
                public_addr: "127.0.0.1:0".into(),
                server_name: Some("localhost".into()),
                cert: "/nonexistent/cert.pem".into(),
                key: "/nonexistent/key.pem".into(),
                cert_reload_secs: 0,
                keep_alive_secs: 15,
                max_idle_timeout_secs: 60,
                max_concurrent_bidi_streams: 64,
            },
            oidc: None,
            postgres: PostgresConfig::default(),
            security: SecurityConfig {
                master_key_env: "CX_TEST_UNSET_MASTER_KEY_999".into(),
                ..SecurityConfig::default()
            },
            dirs: DirsConfig {
                providers: None,
                profiles: None,
                enable_builtin_providers: true,
            },
            bootstrap_users: vec![],
            profiles: vec![ProfileFileConfig {
                name: "github-db".into(),
                provider: "github".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::from([(
                    "token".into(),
                    SecretBinding::Db {
                        scope: SecretScope::Shared,
                        name: "github-shared".into(),
                        field: None,
                    },
                )]),
                virtual_key: None,
                allow: ProfileAllowConfig {
                    groups: vec!["eng".into()],
                    users: vec![],
                },
                routing: ProfileRoutingOverride::default(),
                policy: ProfilePolicyConfig {
                    preset: Some("readonly".into()),
                    rules: vec![],
                },
                allow_insecure_http: false,
            }],
        };

        assert!(resolve_cipher(&cfg).unwrap().is_none());

        let store: Arc<dyn ServerStore> = Arc::new(MemoryStore::new(None));
        let err = start_server_with_store(cfg, store)
            .await
            .err()
            .expect("expected startup to fail without master key when using source=db");
        assert!(
            err.to_string().contains("CX_TEST_UNSET_MASTER_KEY_999"),
            "unexpected error: {err:#}"
        );
    }
}
