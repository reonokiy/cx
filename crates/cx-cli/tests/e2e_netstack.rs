use std::collections::{BTreeMap, VecDeque};
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cx_cli::dns::{FakeIpDns, build_a_query};
use cx_cli::netstack::{AsyncPacketIo, ChannelPacketIo, build_ipv4_udp_packet, run_netstack};
use cx_cli::proxy_fallback::LocalFallbackProxy;
use cx_cli::router::TrafficRouter;
use cx_crypto::{EphemeralCa, VirtualKeyCharset, VirtualKeyFormat, VirtualKeySpec};
use cx_plugin::{
    PlatformRoutingOverride, PlatformSpec, PolicyEffect, PolicyRuleConfig, ProfileSpec,
    SecretBinding,
};
use cx_protocol::{CreateSessionRequest, CreateSessionResponse, DefaultRouteAction};
use cx_server::config::{
    BootstrapUserConfig, DirsConfig, HttpConfig, PostgresConfig, QuicConfig, SecurityConfig,
    ServerFileConfig,
};
use cx_server::store::{MemoryStore, PostgresStore, ServerStore};
use cx_server::start_server_with_store;
use cx_tunnel::{QuicClientTlsOptions, QuicTuning, QuicTunnelClient};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Packet, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const REAL_GITHUB_SECRET: &str = "ghp_REAL_SUPER_SECRET_TOKEN_987654321";
const REAL_OPENAI_SECRET: &str = "sk-REAL_OPENAI_SECRET_KEY_123456789";

/// Spin up a real TLS mock upstream HTTPS server for testing (`api.github.com`, `objects.githubusercontent.com`, `direct.example.org`).
async fn start_mock_https_upstream(
    sans: &[&str],
    handler: impl Fn(String, String, Option<String>, String) -> (StatusCode, String) + Send + Sync + 'static,
) -> (SocketAddr, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    tracing::warn!("mock upstream TLS accept failed");
                    return;
                };
                let io = TokioIo::new(tls);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move {
                        let method = req.method().to_string();
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str().to_string())
                            .unwrap_or_else(|| "/".into());
                        let auth = req
                            .headers()
                            .get(http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(ToString::to_string);
                        let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let body_str = String::from_utf8_lossy(&body_bytes).to_string();

                        let (status, resp_body) = handler(method, path, auth, body_str);
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from(resp_body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    (addr, cert_pem)
}

// --- Client-side virtual smoltcp NIC simulating a child process inside Child NetNS ---

struct ClientMockDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct RxTok(Vec<u8>);
impl RxToken for RxTok {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for TxTok<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}
impl Device for ClientMockDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1500;
        c
    }
}

/// Simulate a child process inside Child NetNS doing a UDP :53 DNS lookup through `cx0`.
async fn virtual_child_dns_lookup(
    child_io: &Arc<ChannelPacketIo>,
    domain: &str,
) -> Option<Ipv4Addr> {
    let query = build_a_query(0x4242, domain);
    let ip_pkt = build_ipv4_udp_packet(
        Ipv4Addr::new(10, 200, 0, 2),
        54321,
        Ipv4Addr::new(10, 200, 0, 1),
        53,
        &query,
    )
    .unwrap();
    child_io.send_packet(&ip_pkt).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let reply_ip = tokio::time::timeout(remaining, child_io.recv_packet())
            .await
            .unwrap()
            .unwrap();
        let Ok(parsed_ip) = Ipv4Packet::new_checked(&reply_ip) else {
            continue;
        };
        if parsed_ip.next_header() != smoltcp::wire::IpProtocol::Udp {
            // Skip any residual TCP FIN/ACK packets from earlier closed connections
            continue;
        }
        let Ok(parsed_udp) = UdpPacket::new_checked(parsed_ip.payload()) else {
            continue;
        };
        if parsed_udp.src_port() != 53 {
            continue;
        }
        let dns = parsed_udp.payload();
        let rcode = dns[3] & 0x0F;
        let ancount = u16::from_be_bytes([dns[6], dns[7]]);
        if rcode != 0 || ancount == 0 {
            return None;
        }
        return Some(Ipv4Addr::new(
            dns[dns.len() - 4],
            dns[dns.len() - 3],
            dns[dns.len() - 2],
            dns[dns.len() - 1],
        ));
    }
}

/// Simulate a raw TCP+TLS+HTTP/1.1 client inside Child NetNS connecting to `(dst_ip, 443)` with `sni_host`
/// over the virtual L3 TUN (`smoltcp` <-> `cx-cli` NetStack -> QUIC -> `cx-server` -> Mock Upstream)!
async fn virtual_child_https_request(
    child_io: &Arc<ChannelPacketIo>,
    dst_ip: Ipv4Addr,
    sni_host: &str,
    trusted_ca_pem: &str,
    raw_http_request: &str,
) -> anyhow::Result<String> {
    let (mut app_stream, stack_stream) = tokio::io::duplex(64 * 1024);
    let (mut stack_r, mut stack_w) = tokio::io::split(stack_stream);
    let io_clone = Arc::clone(child_io);

    let local_port: u16 = 40000 + (rand::random::<u16>() % 20000);
    let pump = tokio::spawn(async move {
        let mut dev = ClientMockDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        };
        let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
        cfg.random_seed = rand::random();
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::now());
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(10, 200, 0, 2), 24));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 200, 0, 1));

        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        let handle = sockets.add(sock);
        sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(
                iface.context(),
                IpEndpoint::new(IpAddress::Ipv4(dst_ip), 443),
                local_port,
            )
            .unwrap();

        let mut pending_out = Vec::<u8>::new();
        let mut read_buf = vec![0u8; 16 * 1024];
        let mut done_writing = false;

        loop {
            iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
            while let Some(p) = dev.tx.pop_front() {
                if io_clone.send_packet(&p).await.is_err() {
                    return;
                }
            }

            let sock = sockets.get_mut::<tcp::Socket>(handle);
            if sock.can_recv() {
                let mut tmp = vec![0u8; 16 * 1024];
                if let Ok(n) = sock.recv_slice(&mut tmp) {
                    if n > 0 && stack_w.write_all(&tmp[..n]).await.is_err() {
                        break;
                    }
                }
            }
            if !pending_out.is_empty() && sock.can_send() {
                if let Ok(n) = sock.send_slice(&pending_out) {
                    pending_out.drain(..n);
                }
            }
            if done_writing && pending_out.is_empty() && sock.state() == TcpState::Established {
                sock.close();
            }
            if matches!(sock.state(), TcpState::Closed | TcpState::CloseWait) {
                let _ = stack_w.shutdown().await;
                if sock.state() == TcpState::Closed {
                    break;
                }
            }

            tokio::select! {
                pkt = io_clone.recv_packet() => {
                    match pkt {
                        Ok(p) => dev.rx.push_back(p),
                        Err(_) => break,
                    }
                }
                read_res = stack_r.read(&mut read_buf), if pending_out.is_empty() && !done_writing => {
                    match read_res {
                        Ok(0) => done_writing = true,
                        Ok(n) => pending_out.extend_from_slice(&read_buf[..n]),
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    });

    let res: anyhow::Result<String> = async {
        let mut roots = RootCertStore::empty();
        let mut reader = BufReader::new(trusted_ca_pem.as_bytes());
        for c in rustls_pemfile::certs(&mut reader) {
            roots.add(c?)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));

        let server_name = ServerName::try_from(sni_host.to_string())?;
        let mut tls = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, &mut app_stream),
        )
        .await??;

        tls.write_all(raw_http_request.as_bytes()).await?;
        tls.flush().await?;

        let mut resp = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp)).await;
        Ok(String::from_utf8_lossy(&resp).to_string())
    }
    .await;

    // ALWAYS abort and await pump so no stale task competes on `child_tun_io`!
    pump.abort();
    let _ = pump.await;
    res
}

#[tokio::test]
async fn end_to_end_netstack_quic_3tier_and_security_controls() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    // 1. Start 3 distinct mock HTTPS upstreams:
    //    - Tier 1 (`api.github.com`): expects REAL secret in Authorization header, echoes body + auth for testing!
    //    - Tier 2 (`objects.githubusercontent.com`): server_tunnel (end-to-end TLS, NO secret injected!)
    //    - Tier 3 (`direct.example.org`): client_passthrough (Host direct dial, NEVER hits cx-server!)
    let (gh_addr, gh_ca_pem) =
        start_mock_https_upstream(&["api.github.com"], |method, path, auth, body| {
            if path == "/echo-secret" {
                // Intentionally echo real secret to prove Response Scrubber strips it!
                return (
                    StatusCode::OK,
                    format!("leaked={REAL_GITHUB_SECRET} auth={}", auth.unwrap_or_default()),
                );
            }
            if path == "/issue" {
                // Verify real secret in Authorization header, while body still has virtual dummy key!
                let auth_ok = auth.as_deref() == Some(&format!("Bearer {REAL_GITHUB_SECRET}"));
                return (
                    StatusCode::OK,
                    format!("method={method} auth_ok={auth_ok} body={body}"),
                );
            }
            let auth_ok = auth.as_deref() == Some(&format!("Bearer {REAL_GITHUB_SECRET}"));
            (StatusCode::OK, format!("github_ok auth_ok={auth_ok} path={path}"))
        })
        .await;

    let (openai_addr, openai_ca_pem) =
        start_mock_https_upstream(&["api.openai.com"], |_method, path, auth, _body| {
            let auth_ok = auth.as_deref() == Some(&format!("Bearer {REAL_OPENAI_SECRET}"));
            let leaked_gh = auth
                .as_deref()
                .map(|a| a.contains(REAL_GITHUB_SECRET))
                .unwrap_or(false);
            (
                StatusCode::OK,
                format!("openai_ok auth_ok={auth_ok} leaked_gh={leaked_gh} path={path}"),
            )
        })
        .await;

    let (cdn_addr, cdn_ca_pem) =
        start_mock_https_upstream(&["objects.githubusercontent.com"], |_m, path, auth, _b| {
            // Tier 2 server_tunnel MUST NOT inject the real GitHub secret!
            let leaked = auth
                .as_deref()
                .map(|a| a.contains(REAL_GITHUB_SECRET))
                .unwrap_or(false);
            (
                StatusCode::OK,
                format!("tier2_cdn_ok leaked={leaked} path={path}"),
            )
        })
        .await;

    let (direct_addr, direct_ca_pem) =
        start_mock_https_upstream(&["direct.example.org"], |_m, path, auth, _b| {
            let leaked = auth
                .as_deref()
                .map(|a| a.contains(REAL_GITHUB_SECRET))
                .unwrap_or(false);
            (
                StatusCode::OK,
                format!("tier3_direct_ok leaked={leaked} path={path}"),
            )
        })
        .await;

    // 2. Write temporary QUIC TLS cert for cx-server
    let tmp_dir = std::env::temp_dir().join(format!("cx-e2e-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let (quic_cert_pem, quic_key_pem) =
        EphemeralCa::generate_dev_server_cert(&["localhost", "127.0.0.1"]).unwrap();
    let quic_cert_path = tmp_dir.join("quic-cert.pem");
    let quic_key_path = tmp_dir.join("quic-key.pem");
    std::fs::write(&quic_cert_path, &quic_cert_pem).unwrap();
    std::fs::write(&quic_key_path, &quic_key_pem).unwrap();

    let mut upstream_overrides = BTreeMap::new();
    upstream_overrides.insert("api.github.com".into(), gh_addr.to_string());
    upstream_overrides.insert("api.openai.com".into(), openai_addr.to_string());
    upstream_overrides.insert("objects.githubusercontent.com".into(), cdn_addr.to_string());

    let profile = ProfileSpec {
        name: "github-ro".into(),
        description: "Multi-platform E2E profile".into(),
        allowed_groups: vec!["eng".into()],
        allowed_users: vec![],
        deny_hosts: vec!["blocked.evil.test".into()],
        fallback: DefaultRouteAction::ClientPassthrough,
        platforms: vec![
            PlatformSpec {
                id: "github".into(),
                provider_id: "github".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::from([(
                    "token".into(),
                    SecretBinding::Inline {
                        value: REAL_GITHUB_SECRET.into(),
                    },
                )]),
                virtual_key_override: Some(VirtualKeySpec {
                    format: VirtualKeyFormat::Random,
                    prefix: "gho_cx_".into(),
                    suffix: String::new(),
                    length: 36,
                    charset: VirtualKeyCharset::Alnum,
                }),
                preset: Some("readonly".into()),
                rules: vec![
                    // Allow POST /issue specifically to test body non-replacement!
                    PolicyRuleConfig {
                        effect: PolicyEffect::Allow,
                        methods: vec!["POST".into()],
                        hosts: vec!["api.github.com".into()],
                        paths: vec!["/issue".into()],
                    },
                ],
                routing: PlatformRoutingOverride::default(),
                allow_insecure_http: false,
            },
            PlatformSpec {
                id: "openai".into(),
                provider_id: "openai".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::from([(
                    "api_key".into(),
                    SecretBinding::Inline {
                        value: REAL_OPENAI_SECRET.into(),
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

    let server_cfg = ServerFileConfig {
        http: HttpConfig {
            listen: "127.0.0.1:0".into(),
            external_url: "http://127.0.0.1".into(),
            trusted_proxies: vec!["127.0.0.1/32".into()],
        },
        quic: QuicConfig {
            listen: "127.0.0.1:0".into(),
            public_addr: "127.0.0.1:0".into(),
            server_name: Some("localhost".into()),
            cert: quic_cert_path,
            key: quic_key_path,
            cert_reload_secs: 0,
            keep_alive_secs: 10,
            max_idle_timeout_secs: 30,
            max_concurrent_bidi_streams: 64,
        },
        oidc: None,
        postgres: PostgresConfig::default(),
        security: SecurityConfig {
            block_private_ips: true,
            allow_private_cidrs: vec![],
            allow_private_targets: false,
            session_ttl_secs: 600,
            master_key_env: "UNUSED".into(),
            master_key_inline: None,
            upstream_overrides,
            extra_upstream_ca_pem: Some(format!("{gh_ca_pem}\n{openai_ca_pem}")),
        },
        dirs: DirsConfig {
            providers: None,
            enable_builtin_providers: true,
        },
        bootstrap_users: vec![
            BootstrapUserConfig {
                email: "alice@example.com".into(),
                display_name: Some("Alice".into()),
                groups: vec!["eng".into(), "cx-admins".into()],
                token: Some("cx_alice_token".into()),
                token_env: None,
            },
            BootstrapUserConfig {
                email: "mallory@example.com".into(),
                display_name: Some("Mallory".into()),
                groups: vec!["interns".into()],
                token: Some("cx_mallory_token".into()),
                token_env: None,
            },
        ],
    };

    // If CX_TEST_PG_PORT is set, run the entire E2E test directly against live PostgreSQL!
    let store: Arc<dyn ServerStore> = if let Ok(pg_port) = std::env::var("CX_TEST_PG_PORT") {
        let pg_cfg = PostgresConfig {
            host: std::env::var("CX_TEST_PG_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: pg_port.parse().expect("invalid CX_TEST_PG_PORT"),
            database: std::env::var("CX_TEST_PG_DB").unwrap_or_else(|_| "cx_test".into()),
            username: std::env::var("CX_TEST_PG_USER").unwrap_or_else(|_| "cx".into()),
            password_env: "UNUSED".into(),
            password: Some(
                std::env::var("CX_TEST_PG_PASSWORD").unwrap_or_else(|_| "cxtestpass".into()),
            ),
            ssl_mode: cx_server::config::PostgresSslMode::Disable,
            max_connections: 8,
        };
        Arc::new(
            PostgresStore::connect(&pg_cfg, None)
                .await
                .expect("failed connecting to live test PostgreSQL"),
        )
    } else {
        Arc::new(MemoryStore::new(None))
    };

    let _ = store.delete_profile(&profile.name).await;
    store
        .create_profile(&profile, "e2e-rev-1", "alice@example.com")
        .await
        .unwrap()
        .expect("seed e2e profile into store");

    let running = start_server_with_store(server_cfg, store).await.unwrap();
    let http_base = format!("http://{}", running.http_addr);
    let http = reqwest::Client::new();

    // 3. Verify Multi-User RBAC: Mallory (not in `eng`) MUST get 403!
    let forbidden = http
        .post(format!("{http_base}/v1/sessions"))
        .bearer_auth("cx_mallory_token")
        .json(&CreateSessionRequest {
            profile: "github-ro".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), reqwest::StatusCode::FORBIDDEN);

    // 4. Alice requests a session (simulating reverse proxy X-Forwarded-For header!)
    let session: CreateSessionResponse = http
        .post(format!("{http_base}/v1/sessions"))
        .bearer_auth("cx_alice_token")
        .header("X-Forwarded-For", "198.51.100.77")
        .json(&CreateSessionRequest {
            profile: "github-ro".into(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let virtual_gh_token = session.client.env_inject.get("GH_TOKEN").unwrap().clone();
    assert!(virtual_gh_token.starts_with("gho_cx_"));
    assert_eq!(virtual_gh_token.len(), "gho_cx_".len() + 36);
    assert_ne!(virtual_gh_token, REAL_GITHUB_SECRET);

    let virtual_openai_token = session
        .client
        .env_inject
        .get("OPENAI_API_KEY")
        .unwrap()
        .clone();
    assert!(virtual_openai_token.starts_with("sk-cx-"));
    assert_ne!(virtual_openai_token, REAL_OPENAI_SECRET);

    // 5. Connect real QUIC tunnel + start Approach 2 `smoltcp` NetStack over virtual L3 TUN!
    let tunnel = QuicTunnelClient::connect(
        session.quic_endpoint.parse().unwrap(),
        &session.quic_server_name,
        &session.session_token,
        &QuicClientTlsOptions {
            extra_ca_pem: Some(quic_cert_pem),
        },
        &QuicTuning::default(),
    )
    .await
    .unwrap();

    let ca = Arc::new(EphemeralCa::generate().unwrap());
    let mut direct_overrides = BTreeMap::new();
    direct_overrides.insert("direct.example.org".into(), direct_addr.to_string());

    let router = Arc::new(TrafficRouter {
        policy: session.routing.clone(),
        profile: session.profile.clone(),
        ca: Arc::clone(&ca),
        tunnel: tunnel.clone(),
        direct_overrides: Arc::new(direct_overrides),
    });

    let (host_tun_io, child_tun_io) = ChannelPacketIo::pair(256);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let stack_task = tokio::spawn(run_netstack(host_tun_io, Arc::clone(&router), shutdown_rx));

    // === TEST A: Tier 0 Deny at Fake-IP DNS layer ===
    assert!(
        virtual_child_dns_lookup(&child_tun_io, "blocked.evil.test")
            .await
            .is_none(),
        "denied host must be refused at DNS layer"
    );

    // === TEST B: Tier 1 `inject` via Fake-IP DNS + smoltcp + Ephemeral CA MITM + QUIC 0x01 ===
    let gh_fake_ip = virtual_child_dns_lookup(&child_tun_io, "api.github.com")
        .await
        .unwrap();
    assert!(FakeIpDns::is_fake_ip(gh_fake_ip));

    let resp = virtual_child_https_request(
        &child_tun_io,
        gh_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        &format!(
            "GET /repos/my-org/cx/pulls HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        resp.contains("github_ok auth_ok=true"),
        "expected real GitHub secret injected on server, got: {resp}"
    );

    // === TEST B2: Second platform (`openai`) in the SAME QUIC session + cross-platform VK isolation! ===
    let oa_fake_ip = virtual_child_dns_lookup(&child_tun_io, "api.openai.com")
        .await
        .unwrap();
    let oa_resp = virtual_child_https_request(
        &child_tun_io,
        oa_fake_ip,
        "api.openai.com",
        ca.ca_pem(),
        &format!(
            "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer {virtual_openai_token}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    )
    .await
    .unwrap();
    assert!(
        oa_resp.contains("openai_ok auth_ok=true leaked_gh=false"),
        "expected OpenAI platform secret injected in same session, got: {oa_resp}"
    );

    // Presenting GitHub's virtual key to OpenAI MUST be rejected (403 INVALID_VIRTUAL_KEY)!
    let cross_vk_resp = virtual_child_https_request(
        &child_tun_io,
        oa_fake_ip,
        "api.openai.com",
        ca.ca_pem(),
        &format!(
            "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer {virtual_gh_token}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    )
    .await
    .unwrap();
    assert!(
        cross_vk_resp.contains("403") && cross_vk_resp.contains("INVALID_VIRTUAL_KEY"),
        "GitHub virtual key must not unlock OpenAI platform secret! got: {cross_vk_resp}"
    );

    // === TEST C: Policy Enforcement (DELETE blocked by readonly preset!) ===
    let denied_resp = virtual_child_https_request(
        &child_tun_io,
        gh_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        &format!(
            "DELETE /repos/my-org/cx HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        denied_resp.contains("403") && denied_resp.contains("POLICY_DENIED"),
        "DELETE must be blocked by readonly policy, got: {denied_resp}"
    );

    // === TEST D: Anti-Reflection (Slot-Only Injection — Body MUST keep virtual key, NOT real secret!) ===
    let body_payload = format!("my_token={virtual_gh_token}");
    let issue_resp = virtual_child_https_request(
        &child_tun_io,
        gh_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        &format!(
            "POST /issue HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer {virtual_gh_token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_payload}",
            body_payload.len()
        ),
    )
    .await
    .unwrap();
    assert!(
        issue_resp.contains("auth_ok=true")
            && issue_resp.contains(&format!("body=my_token={virtual_gh_token}"))
            && !issue_resp.contains(REAL_GITHUB_SECRET),
        "body must NEVER have real secret substituted! got: {issue_resp}"
    );

    // === TEST E: Response Scrubber Defense-in-Depth ===
    let scrub_resp = virtual_child_https_request(
        &child_tun_io,
        gh_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        &format!(
            "GET /echo-secret HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        scrub_resp.contains("[REDACTED]") && !scrub_resp.contains(REAL_GITHUB_SECRET),
        "real secret echoed in response must be scrubbed! got: {scrub_resp}"
    );

    // === TEST F: Anti-SNI-Spoofing Cross-Check (Fake-IP for direct.example.org + SNI api.github.com -> REJECTED!) ===
    let direct_fake_ip = virtual_child_dns_lookup(&child_tun_io, "direct.example.org")
        .await
        .unwrap();
    let spoof_res = virtual_child_https_request(
        &child_tun_io,
        direct_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        "GET /user HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        spoof_res.is_err(),
        "SNI mismatch against Fake-IP DNS must be rejected!"
    );

    // === TEST G: Tier 2 `server_tunnel` (L4 End-to-End TLS via QUIC 0x02, NO MITM CA, NO Secret!) ===
    let cdn_fake_ip = virtual_child_dns_lookup(&child_tun_io, "objects.githubusercontent.com")
        .await
        .unwrap();
    // Notice we trust `cdn_ca_pem` (upstream's real cert!), NOT `ca.ca_pem()` -> PROVES ZERO MITM!
    let cdn_resp = virtual_child_https_request(
        &child_tun_io,
        cdn_fake_ip,
        "objects.githubusercontent.com",
        &cdn_ca_pem,
        &format!(
            "GET /releases/v1.tar.gz HTTP/1.1\r\nHost: objects.githubusercontent.com\r\nAuthorization: Bearer {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        cdn_resp.contains("tier2_cdn_ok leaked=false"),
        "Tier 2 server_tunnel must preserve end-to-end TLS and NEVER inject secret, got: {cdn_resp}"
    );

    // === TEST H: Tier 3 `client_passthrough` (Direct Host Dial, NO MITM, NO cx-server, NO Secret!) ===
    // Trust `direct_ca_pem` (upstream's real cert!) -> PROVES ZERO MITM & ZERO SECRET!
    let direct_resp = virtual_child_https_request(
        &child_tun_io,
        direct_fake_ip,
        "direct.example.org",
        &direct_ca_pem,
        &format!(
            "GET /hello HTTP/1.1\r\nHost: direct.example.org\r\nAuthorization: Bearer {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        direct_resp.contains("tier3_direct_ok leaked=false"),
        "Tier 3 client_passthrough must dial directly without secret leak, got: {direct_resp}"
    );

    // === TEST I: Fallback `--mode proxy` sanity check ===
    let fallback = LocalFallbackProxy::start(Arc::clone(&router), "nonce123").await.unwrap();
    assert_ne!(fallback.addr.port(), 0);

    // A console profile/platform rule update must apply to new requests on an already authenticated tunnel.
    let profile_url = format!("{http_base}/v1/console/profiles/github-ro");
    let current_profile: serde_json::Value = http
        .get(&profile_url)
        .bearer_auth("cx_alice_token")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut updated_platforms: Vec<serde_json::Value> = current_profile["platforms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let mut spec = p["spec"].clone();
            if spec["id"] == "github" {
                spec["rules"] = serde_json::json!([
                    { "effect": "deny", "methods": ["GET"], "hosts": ["api.github.com"], "paths": ["/repos/**"] }
                ]);
            }
            spec
        })
        .collect();
    let updated_profile: serde_json::Value = http
        .put(&profile_url)
        .bearer_auth("cx_alice_token")
        .json(&serde_json::json!({
            "revision": current_profile["revision"],
            "description": current_profile["description"],
            "allowed_groups": current_profile["allowed_groups"],
            "allowed_users": current_profile["allowed_users"],
            "deny_hosts": current_profile["deny_hosts"],
            "fallback": current_profile["fallback"],
            "platforms": updated_platforms,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let updated_response = virtual_child_https_request(
        &child_tun_io,
        gh_fake_ip,
        "api.github.com",
        ca.ca_pem(),
        &format!(
            "GET /repos/my-org/cx/pulls HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token {virtual_gh_token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
    .unwrap();
    assert!(
        updated_response.contains("403") && updated_response.contains("POLICY_DENIED"),
        "console policy must apply on the existing QUIC tunnel, got: {updated_response}"
    );
    // OpenAI platform in the same profile remains completely unaffected!
    let oa_still_ok = virtual_child_https_request(
        &child_tun_io,
        oa_fake_ip,
        "api.openai.com",
        ca.ca_pem(),
        &format!(
            "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer {virtual_openai_token}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    )
    .await
    .unwrap();
    assert!(
        oa_still_ok.contains("openai_ok auth_ok=true"),
        "updating GitHub rules must not affect OpenAI platform, got: {oa_still_ok}"
    );

    // Restore github rules to empty on the profile
    for spec in &mut updated_platforms {
        if spec["id"] == "github" {
            spec["rules"] = serde_json::json!([]);
        }
    }
    http.put(&profile_url)
        .bearer_auth("cx_alice_token")
        .json(&serde_json::json!({
            "revision": updated_profile["revision"],
            "description": current_profile["description"],
            "allowed_groups": current_profile["allowed_groups"],
            "allowed_users": current_profile["allowed_users"],
            "deny_hosts": current_profile["deny_hosts"],
            "fallback": current_profile["fallback"],
            "platforms": updated_platforms,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Close client tunnel cleanly so in-flight L4 server_tunnel streams flush their closing audit rows
    let _ = shutdown_tx.send(true);
    let _ = stack_task.await;
    tunnel.close();

    // Verify audit logs were written in store (4 Tier-1 L7 allow/deny rows + Tier-2 L4 server_tunnel row)
    let mut audit_count = 0;
    for _ in 0..40 {
        audit_count = running.store.count_audit_logs().await.unwrap();
        if audit_count >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        audit_count >= 4,
        "expected >= 4 audit logs for Tier 1 allow/deny and Tier 2 server_tunnel, got {audit_count}"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
