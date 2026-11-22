use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use cx_crypto::constant_time_eq_str;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::router::TrafficRouter;

/// Lightweight fallback `--mode proxy` HTTP CONNECT proxy reusing the exact same `TrafficRouter`.
/// Useful inside restricted containers or Ubuntu hosts where AppArmor restricts unprivileged userns.
pub struct LocalFallbackProxy {
    pub addr: SocketAddr,
    pub expected_basic_auth: String,
}

impl LocalFallbackProxy {
    pub async fn start(router: Arc<TrafficRouter>, nonce: &str) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let expected_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("cx:{nonce}"))
        );

        let auth_check = expected_basic.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let router = Arc::clone(&router);
                let auth_check = auth_check.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let router = Arc::clone(&router);
                        let auth_check = auth_check.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle_proxy_request(req, router, &auth_check).await,
                            )
                        }
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await
                    {
                        debug!(error = %e, "fallback proxy connection closed");
                    }
                });
            }
        });

        Ok(Self {
            addr,
            expected_basic_auth: expected_basic,
        })
    }
}

async fn handle_proxy_request(
    req: Request<Incoming>,
    router: Arc<TrafficRouter>,
    expected_auth: &str,
) -> Response<Full<Bytes>> {
    // Enforce per-exec ephemeral Proxy-Authorization nonce (prevents local multi-user hijacking)
    let presented = req
        .headers()
        .get(http::header::PROXY_AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_eq_str(presented, expected_auth) {
        return Response::builder()
            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
            .header(http::header::PROXY_AUTHENTICATE, "Basic realm=\"cx\"")
            .body(Full::new(Bytes::from("proxy auth required")))
            .unwrap();
    }

    if req.method() == Method::CONNECT {
        let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
        let Some((host, port)) = parse_host_port(authority, 443) else {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("invalid CONNECT authority")))
                .unwrap();
        };

        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);
                    router.dispatch_stream(io, host, port, true).await;
                }
                Err(e) => warn!(error = %e, "CONNECT upgrade failed"),
            }
        });

        return Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }

    // Plain HTTP absolute-URI proxy request
    let host = req
        .uri()
        .host()
        .map(ToString::to_string)
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .unwrap_or_default();
    let port = req.uri().port_u16().unwrap_or(80);
    router.forward_http_via_quic(req, "http", &host, port).await
}

fn parse_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().ok()?;
        Some((h.trim_matches(|c| c == '[' || c == ']').to_string(), port))
    } else {
        Some((authority.to_string(), default_port))
    }
}
