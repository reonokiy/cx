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
use cx_plugin::{HostPatternValidator, ProviderRegistry, ResolvedProfile};
use cx_tunnel::{QuicTuning, QuicTunnelServer};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tracing::{info, warn};

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
        Arc::new(PostgresStore::connect(&cfg.storage.postgres, cipher).await?);
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

pub fn resolve_cipher(cfg: &ServerFileConfig) -> anyhow::Result<EnvelopeCipher> {
    if let Some(b64) = &cfg.storage.master_key_inline {
        Ok(EnvelopeCipher::from_base64(b64)?)
    } else if let Ok(b64) = std::env::var(&cfg.storage.master_key_env) {
        Ok(EnvelopeCipher::from_base64(b64.trim())?)
    } else {
        warn!(
            env = %cfg.storage.master_key_env,
            "master key env not set; using ephemeral in-memory master key (dev only!)"
        );
        Ok(EnvelopeCipher::generate_random().0)
    }
}
