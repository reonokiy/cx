use std::collections::BTreeMap;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use cx_crypto::{SessionClaims, SessionVerifier};
use cx_plugin::{
    InjectionContext, InjectionOutcome, PolicyDecision, ResolvedProfile, ResolvedSecretMap,
    SecretBinding, SecretScope, UpstreamHttpRequest,
};
use cx_protocol::{
    AuthHello, ConnectAck, ConnectMeta, CxGatewayError, RequestMeta, ResponseMeta, RouteDecision,
    write_frame,
};
use cx_tunnel::TunnelHandler;
use http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use quinn::{RecvStream, SendStream};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use secrecy::SecretString;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::scrubber::{scrub_bytes, scrub_headers};
use crate::ssrf::{SsrfPolicy, ssrf_safe_connect};
use crate::store::{AuditEvent, ServerStore};

const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

pub struct AuthenticatedSession {
    pub claims: SessionClaims,
    pub profile: Arc<ResolvedProfile>,
    pub allowed_vk_hashes: Vec<String>,
}

pub struct DataPlaneHandler {
    pub verifier: SessionVerifier,
    pub store: Arc<dyn ServerStore>,
    pub profiles: Arc<BTreeMap<String, Arc<ResolvedProfile>>>,
    pub ssrf_policy: Arc<SsrfPolicy>,
    pub upstream_tls: TlsConnector,
}

impl DataPlaneHandler {
    pub fn build_upstream_tls(extra_ca_pem: Option<&str>) -> anyhow::Result<TlsConnector> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        if let Some(pem) = extra_ca_pem {
            let mut reader = BufReader::new(pem.as_bytes());
            for cert in rustls_pemfile::certs(&mut reader) {
                roots.add(cert?)?;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(tls_cfg)))
    }

    async fn resolve_secret_map(
        &self,
        bindings: &BTreeMap<String, SecretBinding>,
        owner_user_id: &str,
    ) -> Result<ResolvedSecretMap, String> {
        let mut out = BTreeMap::new();
        for (field, binding) in bindings {
            let val = match binding {
                SecretBinding::Env { var } => {
                    let v = std::env::var(var)
                        .map_err(|_| format!("missing environment secret '{var}'"))?;
                    SecretString::from(v)
                }
                SecretBinding::Inline { value } => SecretString::from(value.clone()),
                SecretBinding::Db {
                    scope,
                    name,
                    field: db_field,
                } => {
                    let key_name = db_field.as_deref().unwrap_or(field.as_str());
                    let (scope_str, owner) = match scope {
                        SecretScope::Shared => ("shared", None),
                        SecretScope::Personal => ("personal", Some(owner_user_id)),
                    };
                    let map = self
                        .store
                        .get_encrypted_secret(name, scope_str, owner)
                        .await
                        .map_err(|e| format!("failed decrypting {scope_str} secret '{name}': {e}"))?
                        .ok_or_else(|| format!("{scope_str} secret '{name}' not found in DB"))?;
                    map.get(key_name).cloned().ok_or_else(|| {
                        format!("field '{key_name}' missing in {scope_str} secret '{name}'")
                    })?
                }
            };
            out.insert(field.clone(), val);
        }
        Ok(out)
    }
}

#[async_trait]
impl TunnelHandler for DataPlaneHandler {
    type Session = AuthenticatedSession;

    async fn authenticate(&self, hello: AuthHello) -> Result<Arc<Self::Session>, CxGatewayError> {
        let claims = self
            .verifier
            .verify(&hello.session_token)
            .map_err(|e| CxGatewayError::new("UNAUTHORIZED", e.to_string()))?;

        if self
            .store
            .is_session_revoked(&claims.sid)
            .await
            .unwrap_or(false)
        {
            return Err(CxGatewayError::new("SESSION_REVOKED", "session was revoked"));
        }

        let profile = self
            .profiles
            .get(&claims.profile)
            .cloned()
            .ok_or_else(|| {
                CxGatewayError::new("UNKNOWN_PROFILE", format!("profile '{}' not found", claims.profile))
            })?;

        let mut allowed_vk_hashes = vec![claims.vk_hash.clone()];
        if let Ok(static_hashes) = self
            .store
            .list_active_virtual_key_hashes(&claims.uid, &claims.profile)
            .await
        {
            allowed_vk_hashes.extend(static_hashes);
        }

        info!(
            user = %claims.email,
            profile = %claims.profile,
            sid = %claims.sid,
            client_ip = %claims.client_ip,
            "QUIC session authenticated"
        );

        Ok(Arc::new(AuthenticatedSession {
            claims,
            profile,
            allowed_vk_hashes,
        }))
    }

    async fn handle_l7(
        &self,
        session: Arc<Self::Session>,
        meta: RequestMeta,
        mut send: SendStream,
        mut recv: RecvStream,
    ) {
        let started = Instant::now();
        let route = session.profile.routing.resolve(&meta.host, meta.port);

        let route_tier = match route {
            RouteDecision::Inject => "inject",
            RouteDecision::ServerHttpPassthrough => "server_http_passthrough",
            _ => {
                let reason = format!(
                    "host '{}' is not allowed for L7 processing on profile '{}'",
                    meta.host, session.profile.name
                );
                self.record_l7_audit(
                    &session,
                    &meta,
                    "deny",
                    Some(403),
                    "deny",
                    Some(reason.clone()),
                    started,
                )
                .await;
                let _ = write_l7_error(&mut send, 403, "HOST_NOT_ALLOWED", &reason).await;
                return;
            }
        };

        // L7 policy engine evaluation (deny-by-default)
        if let PolicyDecision::Deny(reason) =
            session
                .profile
                .policy
                .evaluate(&meta.method, &meta.host, &meta.path_and_query)
        {
            self.record_l7_audit(
                &session,
                &meta,
                route_tier,
                Some(403),
                "deny",
                Some(reason.clone()),
                started,
            )
            .await;
            let _ = write_l7_error(&mut send, 403, "POLICY_DENIED", &reason).await;
            return;
        }

        // Read streaming request body up to safety limit
        let mut req_body = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match recv.read(&mut chunk).await {
                Ok(Some(n)) => {
                    if req_body.len() + n > MAX_BODY_BYTES {
                        let _ = write_l7_error(
                            &mut send,
                            413,
                            "PAYLOAD_TOO_LARGE",
                            "request body exceeded limit",
                        )
                        .await;
                        return;
                    }
                    req_body.extend_from_slice(&chunk[..n]);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(error = %e, "failed reading L7 request body from QUIC stream");
                    return;
                }
            }
        }

        let mut upstream_req = UpstreamHttpRequest {
            method: meta.method.clone(),
            scheme: meta.scheme.clone(),
            host: meta.host.clone(),
            port: meta.port,
            path_and_query: meta.path_and_query.clone(),
            headers: meta.headers.clone(),
        };

        // Slot-scoped secret injection (ONLY for Tier 1 `inject`, strictly host + scheme bound)
        let mut secrets_for_scrub: Vec<SecretString> = Vec::new();
        if route == RouteDecision::Inject {
            let matching_injectors: Vec<_> = session
                .profile
                .injectors
                .iter()
                .filter(|inj| inj.matches_target(&upstream_req.host, &upstream_req.scheme))
                .collect();

            if !matching_injectors.is_empty() {
                let secret_map = match self
                    .resolve_secret_map(&session.profile.secret_bindings, &session.claims.uid)
                    .await
                {
                    Ok(m) => m,
                    Err(e) => {
                        self.record_l7_audit(
                            &session,
                            &meta,
                            route_tier,
                            Some(502),
                            "deny",
                            Some(e.clone()),
                            started,
                        )
                        .await;
                        let _ = write_l7_error(&mut send, 502, "SECRET_UNAVAILABLE", &e).await;
                        return;
                    }
                };

                let ctx = InjectionContext {
                    allowed_vk_hashes: &session.allowed_vk_hashes,
                };

                for inj in matching_injectors {
                    match inj.inject(&mut upstream_req, &ctx, &secret_map).await {
                        Ok(InjectionOutcome::Injected) => {
                            debug!(injector = inj.id(), host = %upstream_req.host, "credential injected");
                        }
                        Ok(InjectionOutcome::NoMatchingCredentialPresented) => {}
                        Err(e) => {
                            let msg = e.to_string();
                            self.record_l7_audit(
                                &session,
                                &meta,
                                route_tier,
                                Some(403),
                                "deny",
                                Some(msg.clone()),
                                started,
                            )
                            .await;
                            let _ = write_l7_error(&mut send, 403, "INVALID_VIRTUAL_KEY", &msg).await;
                            return;
                        }
                    }
                }

                secrets_for_scrub.extend(secret_map.into_values());
            }
        }

        // Forward upstream with SSRF-safe dialer and NO automatic redirects.
        match self.forward_upstream(&upstream_req, Bytes::from(req_body)).await {
            Ok((status, mut resp_headers, resp_body)) => {
                let secret_refs: Vec<&SecretString> = secrets_for_scrub.iter().collect();
                scrub_headers(&mut resp_headers, &secret_refs);
                let scrubbed_body = scrub_bytes(&resp_body, &secret_refs);

                // Adjust Content-Length if scrubbing changed body length
                if scrubbed_body.len() != resp_body.len() {
                    resp_headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
                    resp_headers.push((
                        "content-length".into(),
                        scrubbed_body.len().to_string().into_bytes(),
                    ));
                }

                // Commit audit log before completing the QUIC response stream so audit visibility is synchronous.
                self.record_l7_audit(
                    &session,
                    &meta,
                    route_tier,
                    Some(status),
                    "allow",
                    None,
                    started,
                )
                .await;

                let resp_meta = ResponseMeta {
                    status,
                    headers: resp_headers,
                    cx_error: None,
                };
                if write_frame(&mut send, &resp_meta).await.is_ok() {
                    let _ = send.write_all(&scrubbed_body).await;
                    let _ = send.finish();
                }
            }
            Err(err) => {
                let msg = err.to_string();
                self.record_l7_audit(
                    &session,
                    &meta,
                    route_tier,
                    Some(502),
                    "deny",
                    Some(msg.clone()),
                    started,
                )
                .await;
                let _ = write_l7_error(&mut send, 502, "UPSTREAM_ERROR", &msg).await;
            }
        }
    }

    async fn handle_l4(
        &self,
        session: Arc<Self::Session>,
        meta: ConnectMeta,
        mut send: SendStream,
        mut recv: RecvStream,
    ) {
        let started = Instant::now();
        let route = session.profile.routing.resolve(&meta.host, meta.port);
        if route != RouteDecision::ServerTunnel {
            let reason = format!(
                "L4 server_tunnel denied for {}:{} on profile '{}'",
                meta.host, meta.port, session.profile.name
            );
            self.record_l4_audit(&session, &meta, "deny", Some(reason.clone()), started)
                .await;
            let _ = write_frame(
                &mut send,
                &ConnectAck {
                    ok: false,
                    error: Some(CxGatewayError::new("L4_DENIED", reason)),
                },
            )
            .await;
            let _ = send.finish();
            return;
        }

        let mut upstream = match ssrf_safe_connect(&meta.host, meta.port, &self.ssrf_policy).await {
            Ok(s) => s,
            Err(e) => {
                let reason = e.to_string();
                self.record_l4_audit(&session, &meta, "deny", Some(reason.clone()), started)
                    .await;
                let _ = write_frame(
                    &mut send,
                    &ConnectAck {
                        ok: false,
                        error: Some(CxGatewayError::new("UPSTREAM_DIAL_FAILED", reason)),
                    },
                )
                .await;
                let _ = send.finish();
                return;
            }
        };

        if write_frame(&mut send, &ConnectAck { ok: true, error: None })
            .await
            .is_err()
        {
            return;
        }

        let (mut up_r, mut up_w) = upstream.split();
        let c2s = tokio::io::copy(&mut recv, &mut up_w);
        let s2c = tokio::io::copy(&mut up_r, &mut send);
        let _ = tokio::join!(c2s, s2c);
        self.record_l4_audit(&session, &meta, "allow", None, started)
            .await;
        let _ = send.finish();
    }
}

impl DataPlaneHandler {
    async fn forward_upstream(
        &self,
        req: &UpstreamHttpRequest,
        body: Bytes,
    ) -> anyhow::Result<(u16, Vec<(String, Vec<u8>)>, Bytes)> {
        let tcp = ssrf_safe_connect(&req.host, req.port, &self.ssrf_policy).await?;

        let method = Method::from_bytes(req.method.as_bytes())?;
        let uri: Uri = req.path_and_query.parse()?;
        let mut builder = Request::builder().method(method).uri(uri);

        let mut has_host = false;
        for (name, val) in &req.headers {
            if is_hop_by_hop(name) || name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if let (Ok(hn), Ok(hv)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(val),
            ) {
                builder = builder.header(hn, hv);
            }
        }
        if !has_host {
            let host_hdr = if (req.scheme == "https" && req.port == 443)
                || (req.scheme == "http" && req.port == 80)
            {
                req.host.clone()
            } else {
                format!("{}:{}", req.host, req.port)
            };
            builder = builder.header(http::header::HOST, host_hdr);
        }

        let http_req = builder.body(Full::new(body))?;

        let resp = if req.scheme.eq_ignore_ascii_case("https") {
            let server_name = ServerName::try_from(req.host.clone())?;
            let tls_stream = self.upstream_tls.connect(server_name, tcp).await?;
            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!(error = %e, "upstream TLS HTTP/1 connection closed");
                }
            });
            sender.send_request(http_req).await?
        } else {
            let io = TokioIo::new(tcp);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!(error = %e, "upstream HTTP/1 connection closed");
                }
            });
            sender.send_request(http_req).await?
        };

        let status = resp.status().as_u16();
        let mut resp_headers = Vec::new();
        for (k, v) in resp.headers() {
            if is_hop_by_hop(k.as_str()) {
                continue;
            }
            resp_headers.push((k.as_str().to_string(), v.as_bytes().to_vec()));
        }
        let resp_body = resp.into_body().collect().await?.to_bytes();
        Ok((status, resp_headers, resp_body))
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_l7_audit(
        &self,
        session: &AuthenticatedSession,
        meta: &RequestMeta,
        route_tier: &str,
        status_code: Option<u16>,
        decision: &str,
        deny_reason: Option<String>,
        started: Instant,
    ) {
        let path_only = meta
            .path_and_query
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(&meta.path_and_query)
            .to_string();
        if let Err(e) = self
            .store
            .record_audit(&AuditEvent {
                occurred_at: Utc::now().timestamp(),
                user_id: session.claims.uid.clone(),
                user_email: session.claims.email.clone(),
                session_id: session.claims.sid.clone(),
                profile_name: session.profile.name.clone(),
                route_tier: route_tier.to_string(),
                target_host: meta.host.clone(),
                target_port: meta.port,
                http_method: Some(meta.method.clone()),
                http_path: Some(path_only),
                status_code,
                decision: decision.to_string(),
                deny_reason,
                client_ip: session.claims.client_ip.clone(),
                latency_ms: started.elapsed().as_millis() as u64,
            })
            .await
        {
            warn!(error = %e, host = %meta.host, "failed to persist L7 audit event");
        }
    }

    async fn record_l4_audit(
        &self,
        session: &AuthenticatedSession,
        meta: &ConnectMeta,
        decision: &str,
        deny_reason: Option<String>,
        started: Instant,
    ) {
        if let Err(e) = self
            .store
            .record_audit(&AuditEvent {
                occurred_at: Utc::now().timestamp(),
                user_id: session.claims.uid.clone(),
                user_email: session.claims.email.clone(),
                session_id: session.claims.sid.clone(),
                profile_name: session.profile.name.clone(),
                route_tier: "server_tunnel".into(),
                target_host: meta.host.clone(),
                target_port: meta.port,
                http_method: None,
                http_path: None,
                status_code: None,
                decision: decision.to_string(),
                deny_reason,
                client_ip: session.claims.client_ip.clone(),
                latency_ms: started.elapsed().as_millis() as u64,
            })
            .await
        {
            warn!(error = %e, host = %meta.host, "failed to persist L4 audit event");
        }
    }
}

async fn write_l7_error(
    send: &mut SendStream,
    status: u16,
    code: &str,
    message: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "error": code, "message": message }).to_string();
    let meta = ResponseMeta {
        status,
        headers: vec![
            ("content-type".into(), b"application/json".to_vec()),
            ("content-length".into(), body.len().to_string().into_bytes()),
        ],
        cx_error: Some(CxGatewayError::new(code, message)),
    };
    write_frame(send, &meta).await?;
    send.write_all(body.as_bytes()).await?;
    let _ = send.finish();
    Ok(())
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
