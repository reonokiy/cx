use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cx_crypto::EphemeralCa;
use cx_protocol::{
    ConnectMeta, RequestMeta, ResponseMeta, RouteDecision, RoutingPolicy, read_frame,
};
use cx_tunnel::QuicTunnelClient;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto as hyper_auto;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::sni::{PeekedProtocol, PrefixedStream, inspect_first_bytes};

/// Unified 3-Tier Router shared by both Rootless NetNS (`smoltcp`) and `--mode proxy` fallback.
#[derive(Clone)]
pub struct TrafficRouter {
    pub policy: RoutingPolicy,
    pub profile: String,
    pub ca: Arc<EphemeralCa>,
    pub tunnel: QuicTunnelClient,
    /// Optional host -> "ip:port" direct dial override for Tier 3 integration tests.
    pub direct_overrides: Arc<BTreeMap<String, String>>,
}

impl TrafficRouter {
    /// Entry point for transparent TCP streams coming out of `smoltcp` (Approach 2).
    pub async fn handle_transparent_tcp<S>(
        self: Arc<Self>,
        mut stream: S,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        dns_domain: Option<String>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Non-destructively peek first packet with short timeout (so server-speaks-first protocols don't stall)
        let mut peek_buf = vec![0u8; 4096];
        let peeked_len = match tokio::time::timeout(
            Duration::from_millis(200),
            stream.read(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return,
            Err(_) => 0,
        };
        peek_buf.truncate(peeked_len);

        let proto = inspect_first_bytes(&peek_buf);
        let (tls_sni, http_host, is_tls) = match &proto {
            PeekedProtocol::Tls { sni } => (sni.clone(), None, true),
            PeekedProtocol::PlainHttp { host } => (None, host.clone(), false),
            PeekedProtocol::Unknown => (None, None, false),
        };

        // Security cross-check: reject SNI spoofing / domain fronting if Fake-IP domain != TLS SNI!
        if let (Some(d), Some(s)) = (&dns_domain, &tls_sni) {
            if !d.eq_ignore_ascii_case(s) {
                warn!(
                    dns_domain = %d,
                    sni_domain = %s,
                    dst_ip = %dst_ip,
                    "blocked connection: TLS SNI does not match Fake-IP DNS domain"
                );
                return;
            }
        }

        let target_host = dns_domain
            .or(tls_sni)
            .or(http_host)
            .unwrap_or_else(|| dst_ip.to_string());

        let prefixed = PrefixedStream::new(Bytes::from(peek_buf), stream);
        self.dispatch_stream(prefixed, target_host, dst_port, is_tls)
            .await;
    }

    /// Shared 3-tier dispatcher used by both transparent NetNS and CONNECT fallback.
    pub async fn dispatch_stream<S>(
        self: Arc<Self>,
        mut stream: S,
        target_host: String,
        target_port: u16,
        is_tls: bool,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let decision = self.policy.resolve(&target_host, target_port);
        debug!(
            host = %target_host,
            port = target_port,
            decision = ?decision,
            is_tls,
            "routing connection"
        );

        match decision {
            RouteDecision::Deny => {
                warn!(host = %target_host, port = target_port, "connection denied by routing policy");
            }
            RouteDecision::Inject | RouteDecision::ServerHttpPassthrough => {
                if is_tls {
                    if let Err(e) = self
                        .serve_mitm_tls(stream, target_host.clone(), target_port)
                        .await
                    {
                        debug!(host = %target_host, error = %e, "MITM TLS session ended");
                    }
                } else if let Err(e) = self
                    .serve_plain_http(stream, target_host.clone(), target_port)
                    .await
                {
                    debug!(host = %target_host, error = %e, "plain HTTP session ended");
                }
            }
            RouteDecision::ServerTunnel => {
                // Tier 2a: NO TLS termination; forward raw ciphertext via QUIC Stream 0x02
                let meta = ConnectMeta {
                    host: target_host.clone(),
                    port: target_port,
                    profile_hint: Some(self.profile.clone()),
                };
                match self.tunnel.open_l4_stream(&meta).await {
                    Ok((mut q_send, mut q_recv)) => {
                        debug!(host = %target_host, "L4 server_tunnel stream opened; relaying bytes");
                        let (mut c_r, mut c_w) = tokio::io::split(stream);
                        let c2s = tokio::io::copy(&mut c_r, &mut q_send);
                        let s2c = tokio::io::copy(&mut q_recv, &mut c_w);
                        let (r1, r2) = tokio::join!(c2s, s2c);
                        debug!(host = %target_host, c2s = ?r1, s2c = ?r2, "L4 server_tunnel relay ended");
                        let _ = q_send.finish();
                    }
                    Err(e) => {
                        warn!(host = %target_host, error = %e, "L4 server_tunnel failed");
                    }
                }
            }
            RouteDecision::ClientPassthrough => {
                // Tier 3: NO TLS termination, NO cx-server; direct Host NetNS TCP dial!
                let dial_target = self
                    .direct_overrides
                    .get(&target_host.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| format!("{target_host}:{target_port}"));

                match TcpStream::connect(&dial_target).await {
                    Ok(mut upstream) => {
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                    }
                    Err(e) => {
                        debug!(target = %dial_target, error = %e, "Tier 3 client_passthrough dial failed");
                    }
                }
            }
        }
    }

    async fn serve_mitm_tls<S>(
        self: Arc<Self>,
        stream: S,
        target_host: String,
        target_port: u16,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tls_cfg = self.ca.server_config_for_host(&target_host)?;
        let acceptor = TlsAcceptor::from(tls_cfg);
        let tls_stream = acceptor.accept(stream).await?;

        let router = Arc::clone(&self);
        let host = target_host.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let router = Arc::clone(&router);
            let host = host.clone();
            async move {
                Ok::<_, std::convert::Infallible>(
                    router
                        .forward_http_via_quic(req, "https", &host, target_port)
                        .await,
                )
            }
        });

        let io = TokioIo::new(tls_stream);
        hyper_auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    async fn serve_plain_http<S>(
        self: Arc<Self>,
        stream: S,
        target_host: String,
        target_port: u16,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let router = Arc::clone(&self);
        let host = target_host.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let router = Arc::clone(&router);
            let host = host.clone();
            async move {
                Ok::<_, std::convert::Infallible>(
                    router
                        .forward_http_via_quic(req, "http", &host, target_port)
                        .await,
                )
            }
        });

        let io = TokioIo::new(stream);
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    pub async fn forward_http_via_quic(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
        port: u16,
    ) -> Response<Full<Bytes>> {
        let method = req.method().as_str().to_string();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut headers = Vec::new();
        for (k, v) in req.headers() {
            headers.push((k.as_str().to_string(), v.as_bytes().to_vec()));
        }

        let body_bytes = match req.into_body().collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed reading client request body: {e}"),
                );
            }
        };

        let meta = RequestMeta {
            request_id: Uuid::new_v4().to_string(),
            method,
            scheme: scheme.to_string(),
            host: host.to_string(),
            port,
            path_and_query,
            headers,
            profile_hint: Some(self.profile.clone()),
        };

        let (mut q_send, mut q_recv) = match self.tunnel.open_l7_stream(&meta).await {
            Ok(pair) => pair,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed opening QUIC L7 stream: {e}"),
                );
            }
        };

        if let Err(e) = q_send.write_all(&body_bytes).await {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("failed writing body to QUIC stream: {e}"),
            );
        }
        let _ = q_send.finish();

        let resp_meta: ResponseMeta = match read_frame(&mut q_recv).await {
            Ok(m) => m,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed reading ResponseMeta from cx-server: {e}"),
                );
            }
        };

        let resp_body = match q_recv.read_to_end(64 * 1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed reading response body from cx-server: {e}"),
                );
            }
        };

        let status = StatusCode::from_u16(resp_meta.status).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        for (k, v) in resp_meta.headers {
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_bytes(&v),
            ) {
                builder = builder.header(hn, hv);
            }
        }
        builder
            .body(Full::new(Bytes::from(resp_body)))
            .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "response build error"))
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("cx gateway error: {msg}\n"))))
        .unwrap()
}
