pub mod config;
mod console;
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

use arc_swap::ArcSwap;
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
    start_server_with_options(cfg, false).await
}

/// Start server with optional dev seeding (seeds a sample multi-platform `dev` profile when DB is empty).
pub async fn start_server_with_options(
    cfg: ServerFileConfig,
    seed_dev: bool,
) -> anyhow::Result<RunningServer> {
    let cipher = resolve_cipher(&cfg)?;
    let store: Arc<dyn ServerStore> =
        Arc::new(PostgresStore::connect(&cfg.postgres, cipher).await?);
    if seed_dev {
        seed_dev_profile_if_empty(&store).await?;
    }
    start_server_with_store(cfg, store).await
}

async fn seed_dev_profile_if_empty(store: &Arc<dyn ServerStore>) -> anyhow::Result<()> {
    if !store.list_profiles().await?.is_empty() {
        return Ok(());
    }
    use cx_plugin::{
        PlatformRoutingOverride, PlatformSpec, PolicyEffect, PolicyRuleConfig, ProfileSpec,
        SecretScope,
    };
    use cx_protocol::DefaultRouteAction;

    let sample = ProfileSpec {
        name: "dev".into(),
        description: "本地开发示例工作区（GitHub 只读 + OpenAI）".into(),
        allowed_groups: vec!["eng".into(), "cx-admins".into()],
        allowed_users: vec![],
        deny_hosts: vec![],
        fallback: DefaultRouteAction::ClientPassthrough,
        platforms: vec![
            PlatformSpec {
                id: "github".into(),
                provider_id: "github".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::from([(
                    "token".into(),
                    SecretBinding::Db {
                        scope: SecretScope::Shared,
                        name: "dev/github".into(),
                        field: None,
                    },
                )]),
                virtual_key_override: None,
                preset: Some("readonly".into()),
                rules: vec![PolicyRuleConfig {
                    effect: PolicyEffect::Deny,
                    methods: vec!["GET".into()],
                    hosts: vec!["api.github.com".into()],
                    paths: vec!["/repos/example/internal/**".into()],
                }],
                routing: PlatformRoutingOverride::default(),
                allow_insecure_http: false,
            },
            PlatformSpec {
                id: "openai".into(),
                provider_id: "openai".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::from([(
                    "api_key".into(),
                    SecretBinding::Db {
                        scope: SecretScope::Personal,
                        name: "openai".into(),
                        field: None,
                    },
                )]),
                virtual_key_override: None,
                preset: Some("full".into()),
                rules: vec![],
                routing: PlatformRoutingOverride::default(),
                allow_insecure_http: false,
            },
        ],
    };

    let rev = uuid::Uuid::new_v4().to_string();
    let _ = store.create_profile(&sample, &rev, "dev-seed").await?;
    info!("seeded sample multi-platform profile 'dev' (github + openai)");
    Ok(())
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

    // Load provider plugins and resolve all profiles stored in the database
    let validator = HostPatternValidator {
        allow_private_targets: cfg.security.allow_private_targets,
        allow_apex_wildcard: false,
    };
    let registry = ProviderRegistry::new(
        cfg.dirs.providers.clone(),
        cfg.dirs.enable_builtin_providers,
        validator,
    )?;

    let stored_profiles = store.list_profiles().await?;
    let mut resolved_profiles: BTreeMap<String, Arc<ResolvedProfile>> = BTreeMap::new();
    for stored in stored_profiles {
        let resolved = registry.resolve_profile(&stored.spec)?;
        if !store.has_master_key() {
            for platform in resolved.platforms.values() {
                for (field, binding) in &platform.secret_bindings {
                    if matches!(binding, SecretBinding::Db { .. }) {
                        tracing::warn!(
                            profile = %resolved.name,
                            platform = %platform.id,
                            field = %field,
                            master_key_env = %cfg.security.master_key_env,
                            "profile platform binds secret to source = \"db\", but master key is not configured; DB secret writes and decryption will fail closed until set"
                        );
                    }
                }
            }
        }
        let platform_ids: Vec<&str> = resolved.platforms.keys().map(String::as_str).collect();
        info!(
            profile = %resolved.name,
            platforms = ?platform_ids,
            inject_hosts = ?resolved.routing.inject_hosts,
            passthrough_hosts = ?resolved.routing.server_tunnel_hosts,
            "loaded profile from store"
        );
        resolved_profiles.insert(resolved.name.clone(), Arc::new(resolved));
    }
    let profiles = Arc::new(ArcSwap::from_pointee(resolved_profiles));

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
        registry,
        profile_write: tokio::sync::Mutex::new(()),
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
    use crate::config::{DirsConfig, HttpConfig, PostgresConfig, QuicConfig, SecurityConfig};
    use crate::store::MemoryStore;
    use cx_plugin::{PlatformRoutingOverride, PlatformSpec, ProfileSpec, SecretScope};
    use cx_protocol::DefaultRouteAction;

    #[tokio::test]
    async fn db_secret_fails_closed_without_master_key_without_blocking_boot() {
        let dir = std::env::temp_dir().join(format!("cx-boot-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_pem, key_pem) =
            cx_crypto::EphemeralCa::generate_dev_server_cert(&["localhost", "127.0.0.1"]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();

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
                cert: cert_path,
                key: key_path,
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
                enable_builtin_providers: true,
            },
            bootstrap_users: vec![],
        };

        assert!(resolve_cipher(&cfg).unwrap().is_none());

        let store: Arc<dyn ServerStore> = Arc::new(MemoryStore::new(None));
        store
            .create_profile(
                &ProfileSpec {
                    name: "github-db".into(),
                    description: String::new(),
                    allowed_groups: vec!["eng".into()],
                    allowed_users: vec![],
                    deny_hosts: vec![],
                    fallback: DefaultRouteAction::ClientPassthrough,
                    platforms: vec![PlatformSpec {
                        id: "github".into(),
                        provider_id: "github".into(),
                        params: BTreeMap::new(),
                        secrets: BTreeMap::from([(
                            "token".into(),
                            SecretBinding::Db {
                                scope: SecretScope::Shared,
                                name: "github-shared".into(),
                                field: None,
                            },
                        )]),
                        virtual_key_override: None,
                        preset: Some("readonly".into()),
                        rules: vec![],
                        routing: PlatformRoutingOverride::default(),
                        allow_insecure_http: false,
                    }],
                },
                "rev-1",
                "test@example.com",
            )
            .await
            .unwrap();

        let running = start_server_with_store(cfg, Arc::clone(&store))
            .await
            .expect("server should boot cleanly even without master key");
        assert!(running.http_addr.port() > 0);

        let err = store
            .upsert_encrypted_secret(
                "github-shared",
                "shared",
                None,
                &BTreeMap::from([("token".into(), "secret".into())]),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::store::StoreError::MasterKeyNotConfigured),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
