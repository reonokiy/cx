use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use cx_crypto::{
    SessionClaims, SessionSigner, constant_time_eq_str, generate_random_token, hash_secret_hex,
};
use cx_plugin::{ProviderRegistry, ResolvedProfile};
use cx_protocol::{
    CliLoginPollRequest, CliLoginPollResponse, CliLoginStartResponse, CreateScopedTokenRequest,
    CreateScopedTokenResponse, CreateSessionRequest, CreateSessionResponse,
    CreateVirtualKeyRequest, CreateVirtualKeyResponse, ProfilePlatformSummary, ProfileSummary,
    UpsertSecretRequest, UserSummary,
};
use ipnet::IpNet;
use serde::Deserialize;
use uuid::Uuid;

use crate::oidc::OidcClient;
use crate::store::{AuthPrincipal, CliLoginRecord, ServerStore, UserRecord};

pub struct ControlPlaneState {
    pub external_url: String,
    pub quic_public_addr: String,
    pub quic_server_name: String,
    pub session_ttl_secs: u64,
    pub trusted_proxies: Vec<IpNet>,
    pub admin_groups: Vec<String>,
    pub signer: SessionSigner,
    pub store: Arc<dyn ServerStore>,
    pub oidc: Option<Arc<OidcClient>>,
    pub profiles: Arc<ArcSwap<BTreeMap<String, Arc<ResolvedProfile>>>>,
    pub registry: ProviderRegistry,
    pub profile_write: tokio::sync::Mutex<()>,
}

pub fn build_router(state: Arc<ControlPlaneState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/cli/start", post(cli_login_start))
        .route("/auth/cli", get(cli_login_browser_start))
        .route("/v1/auth/oidc/callback", get(oidc_callback))
        .route("/v1/auth/cli/poll", post(cli_login_poll))
        .route("/v1/whoami", get(whoami))
        .route("/v1/profiles", get(list_profiles))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/{id}", delete(revoke_session))
        .route("/v1/tokens", post(create_scoped_token))
        .route("/v1/virtual-keys", post(create_virtual_key))
        .route("/v1/secrets", post(upsert_secret))
        .merge(crate::console::router())
        .layer(axum::middleware::map_response(
            |mut response: axum::response::Response| async move {
                response
                    .headers_mut()
                    .entry(axum::http::header::CACHE_CONTROL)
                    .or_insert(axum::http::HeaderValue::from_static("no-store"));
                response
            },
        ))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

fn extract_client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> String {
    let peer_trusted = trusted_proxies.iter().any(|net| net.contains(&peer.ip()));
    if peer_trusted {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next().map(str::trim) {
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let trimmed = real_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    peer.ip().to_string()
}

pub(crate) const CONSOLE_SESSION_COOKIE: &str = "cx_console_session";
pub(crate) const CONSOLE_OIDC_TX_COOKIE: &str = "cx_oidc_tx";
pub(crate) const CONSOLE_CSRF_HEADER: &str = "x-cx-console";
pub(crate) const WEB_OIDC_PENDING_STATUS: &str = "web_pending";
pub(crate) const WEB_SESSION_TTL_SECS: i64 = 24 * 3600;

pub(crate) fn is_https_external_url(external_url: &str) -> bool {
    external_url
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("https://")
}

pub(crate) fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for raw in headers.get_all(header::COOKIE) {
        let Ok(cookie_header) = raw.to_str() else {
            continue;
        };
        for pair in cookie_header.split(';') {
            let Some((k, v)) = pair.trim().split_once('=') else {
                continue;
            };
            if k.trim() == name {
                let value = v.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

pub(crate) fn build_cookie(name: &str, value: &str, max_age_secs: i64, secure: bool) -> String {
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{secure_attr}"
    )
}

pub(crate) fn check_console_csrf(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let has_header = headers
        .get(CONSOLE_CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1");
    if !has_header {
        return Err((
            StatusCode::FORBIDDEN,
            "missing required X-CX-Console header for cookie authentication".into(),
        ));
    }
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if site.eq_ignore_ascii_case("cross-site") {
            return Err((
                StatusCode::FORBIDDEN,
                "cross-site cookie authentication is forbidden".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn authenticate_request(
    state: &ControlPlaneState,
    headers: &HeaderMap,
) -> Result<AuthPrincipal, (StatusCode, String)> {
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .map(str::trim)
            .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer token".into()))?;

        return state
            .store
            .verify_access_token(token)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "invalid or expired token".into()));
    }

    if let Some(cookie_token) = extract_cookie(headers, CONSOLE_SESSION_COOKIE) {
        check_console_csrf(headers)?;
        return state
            .store
            .verify_access_token(&cookie_token)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or((StatusCode::UNAUTHORIZED, "invalid or expired session".into()));
    }

    Err((StatusCode::UNAUTHORIZED, "missing Authorization header".into()))
}

fn to_user_summary(u: &UserRecord) -> UserSummary {
    UserSummary {
        id: u.id.clone(),
        email: u.email.clone(),
        display_name: u.display_name.clone(),
        groups: u.groups.clone(),
    }
}

// --- OIDC Server-Relayed CLI Login ---

async fn cli_login_start(
    State(state): State<Arc<ControlPlaneState>>,
) -> Result<Json<CliLoginStartResponse>, (StatusCode, String)> {
    if state.oidc.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "OIDC is not configured on this server; use `cx login --token <pat>`".into(),
        ));
    }
    let login_id = Uuid::new_v4().to_string();
    let user_code = format!(
        "{}-{}",
        generate_random_token("", 4).to_ascii_uppercase(),
        generate_random_token("", 4).to_ascii_uppercase()
    );
    let poll_secret = generate_random_token("cxpoll_", 32);
    let oidc_state = generate_random_token("cxst_", 24);
    let oidc_nonce = generate_random_token("cxnc_", 24);
    let pkce_verifier = generate_random_token("", 48);
    let expires_in_secs = 300u64;
    let expires_at = Utc::now().timestamp() + expires_in_secs as i64;

    state
        .store
        .create_cli_login(&CliLoginRecord {
            login_id: login_id.clone(),
            user_code: user_code.clone(),
            poll_secret_hash: hash_secret_hex(&poll_secret),
            oidc_state,
            oidc_nonce,
            pkce_verifier,
            status: "pending".into(),
            approved_token: None,
            approved_user_id: None,
            expires_at,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let verification_url = format!(
        "{}/auth/cli?code={}",
        state.external_url.trim_end_matches('/'),
        user_code
    );

    Ok(Json(CliLoginStartResponse {
        login_id,
        user_code,
        poll_secret,
        verification_url,
        expires_in_secs,
    }))
}

#[derive(Deserialize)]
struct BrowserLoginQuery {
    code: String,
}

async fn cli_login_browser_start(
    State(state): State<Arc<ControlPlaneState>>,
    Query(q): Query<BrowserLoginQuery>,
) -> Result<Redirect, (StatusCode, String)> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "OIDC not configured".into()))?;
    let rec = state
        .store
        .get_cli_login_by_code(&q.code)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "invalid login code".into()))?;

    if rec.status != "pending" || Utc::now().timestamp() > rec.expires_at {
        return Err((StatusCode::GONE, "login code expired or already used".into()));
    }

    let auth_url = oidc
        .build_authorize_url(&rec.oidc_state, &rec.oidc_nonce, &rec.pkce_verifier)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("OIDC error: {e}")))?;

    Ok(Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn web_oidc_error_redirect(code: &str, secure: bool) -> Response {
    let mut response = Redirect::to(&format!("/ui/?auth_error={code}")).into_response();
    if let Ok(clear_tx) = HeaderValue::from_str(&build_cookie(CONSOLE_OIDC_TX_COOKIE, "", 0, secure))
    {
        response.headers_mut().append(header::SET_COOKIE, clear_tx);
    }
    response
}

async fn oidc_callback(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Query(q): Query<OidcCallbackQuery>,
) -> Result<Response, (StatusCode, String)> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "OIDC not configured".into()))?;

    let secure = is_https_external_url(&state.external_url);
    let Some(state_param) = q.state.as_deref() else {
        return Err((StatusCode::BAD_REQUEST, "missing OIDC state".into()));
    };

    let rec = state
        .store
        .get_cli_login_by_state(state_param)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let Some(rec) = rec else {
        if state_param.starts_with("cxweb_") {
            return Ok(web_oidc_error_redirect("oidc_expired", secure));
        }
        return Err((StatusCode::BAD_REQUEST, "unknown OIDC state".into()));
    };

    if rec.status == WEB_OIDC_PENDING_STATUS || rec.oidc_state.starts_with("cxweb_") {
        if rec.status != WEB_OIDC_PENDING_STATUS {
            return Ok(web_oidc_error_redirect("oidc_expired", secure));
        }
        let tx_ok = extract_cookie(&headers, CONSOLE_OIDC_TX_COOKIE)
            .is_some_and(|tx| constant_time_eq_str(&hash_secret_hex(&tx), &rec.poll_secret_hash));
        if !tx_ok {
            return Ok(web_oidc_error_redirect("oidc_invalid_session", secure));
        }

        if let Some(err_code) = q.error.as_deref() {
            let _ = state
                .store
                .consume_cli_login_if_status(&rec.login_id, WEB_OIDC_PENDING_STATUS)
                .await;
            tracing::warn!(
                error = %err_code,
                description = ?q.error_description,
                "web console OIDC provider returned error"
            );
            let mapped = if err_code == "access_denied" {
                "oidc_access_denied"
            } else {
                "oidc_failed"
            };
            return Ok(web_oidc_error_redirect(mapped, secure));
        }

        if Utc::now().timestamp() > rec.expires_at {
            let _ = state
                .store
                .consume_cli_login_if_status(&rec.login_id, WEB_OIDC_PENDING_STATUS)
                .await;
            return Ok(web_oidc_error_redirect("oidc_expired", secure));
        }

        let Some(code) = q.code.as_deref() else {
            return Ok(web_oidc_error_redirect("oidc_failed", secure));
        };

        let claimed = state
            .store
            .consume_cli_login_if_status(&rec.login_id, WEB_OIDC_PENDING_STATUS)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if !claimed {
            return Ok(web_oidc_error_redirect("oidc_expired", secure));
        }

        let identity = match oidc
            .exchange_and_verify(code, &rec.pkce_verifier, &rec.oidc_nonce)
            .await
        {
            Ok(id) => id,
            Err(err) => {
                tracing::warn!(error = %err, "web console OIDC token verification failed");
                return Ok(web_oidc_error_redirect("oidc_verification_failed", secure));
            }
        };

        let user = state
            .store
            .upsert_user(
                &identity.issuer,
                &identity.subject,
                &identity.email,
                &identity.display_name,
                &identity.groups,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let raw_access_token = generate_random_token("cx_web_", 40);
        let token_exp = Utc::now().timestamp() + WEB_SESSION_TTL_SECS;
        state
            .store
            .insert_access_token(
                &user.id,
                "oidc-web-console",
                &raw_access_token,
                None,
                token_exp,
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut response = Redirect::to("/ui/").into_response();
        let session_cookie = build_cookie(
            CONSOLE_SESSION_COOKIE,
            &raw_access_token,
            WEB_SESSION_TTL_SECS,
            secure,
        );
        let clear_tx_cookie = build_cookie(CONSOLE_OIDC_TX_COOKIE, "", 0, secure);
        if let Ok(val) = HeaderValue::from_str(&session_cookie) {
            response.headers_mut().append(header::SET_COOKIE, val);
        }
        if let Ok(val) = HeaderValue::from_str(&clear_tx_cookie) {
            response.headers_mut().append(header::SET_COOKIE, val);
        }
        return Ok(response);
    }

    if let Some(err_code) = q.error {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!(
                "OIDC provider returned error: {err_code}{}",
                q.error_description
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default()
            ),
        ));
    }

    if rec.status != "pending" || Utc::now().timestamp() > rec.expires_at {
        return Err((StatusCode::GONE, "login session expired".into()));
    }

    let Some(code) = q.code else {
        return Err((StatusCode::BAD_REQUEST, "missing OIDC authorization code".into()));
    };

    let identity = oidc
        .exchange_and_verify(&code, &rec.pkce_verifier, &rec.oidc_nonce)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("OIDC verification failed: {e}")))?;

    let user = state
        .store
        .upsert_user(
            &identity.issuer,
            &identity.subject,
            &identity.email,
            &identity.display_name,
            &identity.groups,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let raw_access_token = generate_random_token("cx_at_", 40);
    let token_exp = Utc::now().timestamp() + 7 * 24 * 3600;
    state
        .store
        .insert_access_token(&user.id, "oidc-cli-login", &raw_access_token, None, token_exp)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .store
        .approve_cli_login(&rec.login_id, &user.id, &raw_access_token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Html(format!(
        "<html><body><h2>cx login succeeded</h2><p>Signed in as <b>{}</b>. You may close this tab and return to your terminal.</p></body></html>",
        escape_html(&user.email)
    ))
    .into_response())
}

async fn cli_login_poll(
    State(state): State<Arc<ControlPlaneState>>,
    Json(req): Json<CliLoginPollRequest>,
) -> Result<Json<CliLoginPollResponse>, (StatusCode, String)> {
    let rec = state
        .store
        .get_cli_login_by_id(&req.login_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "unknown login_id".into()))?;

    if rec.status == WEB_OIDC_PENDING_STATUS {
        return Err((StatusCode::BAD_REQUEST, "not a CLI login session".into()));
    }

    if !constant_time_eq_str(&hash_secret_hex(&req.poll_secret), &rec.poll_secret_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid poll_secret".into()));
    }

    if Utc::now().timestamp() > rec.expires_at && rec.status == "pending" {
        return Ok(Json(CliLoginPollResponse {
            status: "expired".into(),
            access_token: None,
            user: None,
        }));
    }

    if rec.status == "approved" {
        let user = match rec.approved_user_id.as_deref() {
            Some(uid) => state
                .store
                .get_user_by_id(uid)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .map(|u| to_user_summary(&u)),
            None => None,
        };
        let _ = state.store.consume_cli_login(&rec.login_id).await;
        return Ok(Json(CliLoginPollResponse {
            status: "approved".into(),
            access_token: rec.approved_token,
            user,
        }));
    }

    Ok(Json(CliLoginPollResponse {
        status: rec.status,
        access_token: None,
        user: None,
    }))
}

// --- Identity, Profiles, Sessions & Keys ---

async fn whoami(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Json<UserSummary>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    Ok(Json(to_user_summary(&principal.user)))
}

async fn list_profiles(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ProfileSummary>>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let list = state
        .profiles
        .load()
        .values()
        .filter(|p| {
            let group_ok = p.user_has_access(
                &principal.user.id,
                &principal.user.email,
                &principal.user.groups,
            );
            let scope_ok = principal
                .allowed_profiles
                .as_ref()
                .map(|allowed| allowed.iter().any(|a| a == &p.name))
                .unwrap_or(true);
            group_ok && scope_ok
        })
        .map(|p| ProfileSummary {
            name: p.name.clone(),
            description: p.description.clone(),
            platforms: p
                .platforms
                .values()
                .map(|plat| ProfilePlatformSummary {
                    id: plat.id.clone(),
                    provider_id: plat.provider_id.clone(),
                    inject_hosts: plat.inject_hosts.clone(),
                    server_tunnel_hosts: plat.server_tunnel_hosts.clone(),
                })
                .collect(),
            inject_hosts: p.routing.inject_hosts.clone(),
            server_tunnel_hosts: p.routing.server_tunnel_hosts.clone(),
            default_action: p.routing.default_action,
        })
        .collect();
    Ok(Json(list))
}

async fn create_session(
    State(state): State<Arc<ControlPlaneState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let profile = state
        .profiles
        .load_full()
        .get(&req.profile)
        .cloned()
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("profile '{}' not found", req.profile),
        ))?;

    if !profile.user_has_access(
        &principal.user.id,
        &principal.user.email,
        &principal.user.groups,
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("user lacks RBAC access to profile '{}'", req.profile),
        ));
    }
    if let Some(allowed) = &principal.allowed_profiles {
        if !allowed.iter().any(|p| p == &req.profile) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("scoped token cannot access profile '{}'", req.profile),
            ));
        }
    }

    let session_id = format!("sess_{}", Uuid::new_v4().simple());
    let ephemeral_vks = profile.generate_ephemeral_virtual_keys();
    let vk_hashes: BTreeMap<String, String> = ephemeral_vks
        .iter()
        .map(|(platform_id, vk)| (platform_id.clone(), hash_secret_hex(vk)))
        .collect();
    let now = Utc::now().timestamp();
    let exp = now + state.session_ttl_secs as i64;
    let client_ip = extract_client_ip(peer, &headers, &state.trusted_proxies);

    let claims = SessionClaims {
        sid: session_id.clone(),
        uid: principal.user.id.clone(),
        email: principal.user.email.clone(),
        groups: principal.user.groups.clone(),
        profile: profile.name.clone(),
        vk_hashes,
        client_ip,
        iat: now,
        exp,
    };

    let session_token = state
        .signer
        .sign(&claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let client = profile.build_client_launch_spec(&ephemeral_vks);

    Ok(Json(CreateSessionResponse {
        session_id,
        session_token,
        expires_at: exp,
        quic_endpoint: state.quic_public_addr.clone(),
        quic_server_name: state.quic_server_name.clone(),
        profile: profile.name.clone(),
        routing: profile.routing.clone(),
        client,
    }))
}

async fn revoke_session(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = authenticate_request(&state, &headers).await?;
    state
        .store
        .revoke_session(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_scoped_token(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<CreateScopedTokenRequest>,
) -> Result<Json<CreateScopedTokenResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    if principal.allowed_profiles.as_ref().is_some_and(|allowed| {
        req.profiles.is_empty()
            || req
                .profiles
                .iter()
                .any(|profile| !allowed.contains(profile))
    }) {
        return Err((
            StatusCode::FORBIDDEN,
            "token cannot grant broader profile access".into(),
        ));
    }
    let profiles = state.profiles.load_full();
    for p in &req.profiles {
        let Some(prof) = profiles.get(p) else {
            return Err((StatusCode::NOT_FOUND, format!("profile '{p}' not found")));
        };
        if !prof.user_has_access(
            &principal.user.id,
            &principal.user.email,
            &principal.user.groups,
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("cannot grant access to profile '{p}'"),
            ));
        }
    }

    let raw_token = generate_random_token("cx_pat_", 40);
    let ttl = req.ttl_secs.unwrap_or(30 * 24 * 3600);
    let expires_at = Utc::now().timestamp() + ttl as i64;
    let profiles_opt = if req.profiles.is_empty() {
        None
    } else {
        Some(req.profiles.as_slice())
    };
    let id = state
        .store
        .insert_access_token(
            &principal.user.id,
            &req.name,
            &raw_token,
            profiles_opt,
            expires_at,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateScopedTokenResponse {
        id,
        token: raw_token,
        expires_at,
    }))
}

async fn create_virtual_key(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<CreateVirtualKeyRequest>,
) -> Result<Json<CreateVirtualKeyResponse>, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    let profile = state
        .profiles
        .load_full()
        .get(&req.profile)
        .cloned()
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("profile '{}' not found", req.profile),
        ))?;
    if !profile.user_has_access(
        &principal.user.id,
        &principal.user.email,
        &principal.user.groups,
    ) {
        return Err((StatusCode::FORBIDDEN, "forbidden for this profile".into()));
    }

    if principal
        .allowed_profiles
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&req.profile))
    {
        return Err((
            StatusCode::FORBIDDEN,
            "token cannot access this profile".into(),
        ));
    }
    let platform = match req.platform.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(plat_id) => profile.platforms.get(plat_id).ok_or((
            StatusCode::NOT_FOUND,
            format!("platform '{}' not found in profile '{}'", plat_id, profile.name),
        ))?,
        None if profile.platforms.len() == 1 => profile.platforms.values().next().unwrap(),
        None if profile.platforms.is_empty() => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("profile '{}' has no attached platforms", profile.name),
            ));
        }
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "profile '{}' has multiple platforms; specify 'platform'",
                    profile.name
                ),
            ));
        }
    };

    let vk = platform.virtual_key.generate();
    let expires_at = req
        .ttl_secs
        .map(|seconds| {
            i64::try_from(seconds)
                .ok()
                .filter(|seconds| *seconds > 0)
                .and_then(|seconds| Utc::now().timestamp().checked_add(seconds))
                .ok_or((StatusCode::BAD_REQUEST, "invalid key lifetime".into()))
        })
        .transpose()?;
    let id = state
        .store
        .create_virtual_key(&principal.user.id, &profile.name, &platform.id, &vk, expires_at)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateVirtualKeyResponse {
        id,
        virtual_key: vk,
        profile: profile.name.clone(),
        platform: platform.id.clone(),
        expires_at,
    }))
}

async fn upsert_secret(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(req): Json<UpsertSecretRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let principal = authenticate_request(&state, &headers).await?;
    if principal.allowed_profiles.is_some() {
        return Err((
            StatusCode::FORBIDDEN,
            "unscoped token required to update secrets".into(),
        ));
    }
    let owner = match req.scope.as_str() {
        "shared" => {
            let is_admin = principal
                .user
                .groups
                .iter()
                .any(|g| state.admin_groups.iter().any(|ag| ag == g));
            if !is_admin {
                return Err((
                    StatusCode::FORBIDDEN,
                    "admin group membership required for shared secrets".into(),
                ));
            }
            None
        }
        "personal" => Some(principal.user.id.as_str()),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "scope must be 'shared' or 'personal'".into(),
            ));
        }
    };

    state
        .store
        .upsert_encrypted_secret(&req.name, &req.scope, owner, &req.fields)
        .await
        .map_err(|e| match e {
            crate::store::StoreError::MasterKeyNotConfigured => {
                (StatusCode::SERVICE_UNAVAILABLE, e.to_string())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(StatusCode::NO_CONTENT)
}
