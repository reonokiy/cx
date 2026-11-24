use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use cx_crypto::{generate_random_token, hash_secret_hex};
use cx_plugin::{
    PlatformSpec, PolicyRuleConfig, ProfileSpec, ProviderCatalogEntry, ResolvedProfile,
    SecretBinding, SecretScope,
};
use cx_protocol::DefaultRouteAction;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::controlplane::{
    CONSOLE_OIDC_TX_COOKIE, CONSOLE_SESSION_COOKIE, ControlPlaneState, WEB_OIDC_PENDING_STATUS,
    authenticate_request, build_cookie, check_console_csrf, extract_cookie, is_https_external_url,
};
use crate::store::{
    AuditEntry, AuditFilter, AuthPrincipal, CliLoginRecord, SecretMeta, StoreError, StoredProfile,
};

type ApiError = (StatusCode, String);

pub fn router() -> Router<Arc<ControlPlaneState>> {
    Router::new()
        .route("/", get(|| async { Redirect::temporary("/ui/") }))
        .route("/ui", get(|| async { Redirect::permanent("/ui/") }))
        .route("/ui/", get(|| async { serve_asset("index.html").await }))
        .route("/ui/assets/{file}", get(asset))
        .route("/v1/console/auth-config", get(auth_config))
        .route("/v1/console/auth/oidc/start", get(oidc_start))
        .route("/v1/console/auth/logout", post(logout))
        .route("/v1/console", get(context))
        .route("/v1/console/profiles", post(create_profile))
        .route(
            "/v1/console/profiles/{profile}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
        .route("/v1/console/audit", get(audit))
}

#[derive(Serialize)]
struct ConsoleAuthConfig {
    oidc_enabled: bool,
    session_active: bool,
}

async fn auth_config(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Json<ConsoleAuthConfig> {
    let session_active = match extract_cookie(&headers, CONSOLE_SESSION_COOKIE) {
        Some(cookie_token) => state
            .store
            .verify_access_token(&cookie_token)
            .await
            .ok()
            .flatten()
            .is_some(),
        None => false,
    };
    Json(ConsoleAuthConfig {
        oidc_enabled: state.oidc.is_some(),
        session_active,
    })
}

async fn oidc_start(State(state): State<Arc<ControlPlaneState>>) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return Redirect::to("/ui/?auth_error=oidc_not_configured").into_response();
    };

    let login_id = Uuid::new_v4().to_string();
    let user_code = format!("WEB-{}", generate_random_token("", 16));
    let tx_secret = generate_random_token("cxtx_", 32);
    let oidc_state = generate_random_token("cxweb_", 24);
    let oidc_nonce = generate_random_token("cxnc_", 24);
    let pkce_verifier = generate_random_token("", 48);
    let expires_in_secs = 300i64;
    let expires_at = Utc::now().timestamp() + expires_in_secs;

    if let Err(error) = state
        .store
        .create_cli_login(&CliLoginRecord {
            login_id,
            user_code,
            poll_secret_hash: hash_secret_hex(&tx_secret),
            oidc_state: oidc_state.clone(),
            oidc_nonce: oidc_nonce.clone(),
            pkce_verifier: pkce_verifier.clone(),
            status: WEB_OIDC_PENDING_STATUS.into(),
            approved_token: None,
            approved_user_id: None,
            expires_at,
        })
        .await
    {
        tracing::error!(%error, "failed persisting web console OIDC login state");
        return Redirect::to("/ui/?auth_error=oidc_failed").into_response();
    }

    let auth_url = match oidc
        .build_authorize_url(&oidc_state, &oidc_nonce, &pkce_verifier)
        .await
    {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(%error, "failed building OIDC authorize URL for web console");
            return Redirect::to("/ui/?auth_error=oidc_provider_unreachable").into_response();
        }
    };

    let secure = is_https_external_url(&state.external_url);
    let mut response = Redirect::temporary(&auth_url).into_response();
    if let Ok(val) = HeaderValue::from_str(&build_cookie(
        CONSOLE_OIDC_TX_COOKIE,
        &tx_secret,
        expires_in_secs,
        secure,
    )) {
        response.headers_mut().append(header::SET_COOKIE, val);
    }
    response
}

async fn logout(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_console_csrf(&headers)?;
    if let Some(cookie_token) = extract_cookie(&headers, CONSOLE_SESSION_COOKIE) {
        if let Err(error) = state.store.revoke_access_token(&cookie_token).await {
            tracing::error!(%error, "failed revoking console session token on logout");
        }
    }
    let secure = is_https_external_url(&state.external_url);
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Ok(clear_session) =
        HeaderValue::from_str(&build_cookie(CONSOLE_SESSION_COOKIE, "", 0, secure))
    {
        response
            .headers_mut()
            .append(header::SET_COOKIE, clear_session);
    }
    Ok(response)
}

async fn asset(Path(file): Path<String>) -> Response {
    if !file
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        || ![".js", ".css", ".woff2"]
            .iter()
            .any(|suffix| file.ends_with(suffix))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_asset(&format!("assets/{file}")).await
}

async fn serve_asset(file: &str) -> Response {
    let root = std::env::var_os("CX_WEB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("web/dist"));
    let content_type = match file.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        _ => "font/woff2",
    };
    match tokio::fs::read(root.join(file)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, content_type),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                (header::CACHE_CONTROL, "no-cache"),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(_) if file == "index.html" => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Web console assets are unavailable. Build web/dist or set CX_WEB_DIR.",
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn is_admin(state: &ControlPlaneState, principal: &AuthPrincipal) -> bool {
    principal.allowed_profiles.is_none()
        && principal
            .user
            .groups
            .iter()
            .any(|group| state.admin_groups.contains(group))
}

async fn require_admin(
    state: &ControlPlaneState,
    headers: &HeaderMap,
) -> Result<AuthPrincipal, ApiError> {
    let principal = authenticate_request(state, headers).await?;
    if !is_admin(state, &principal) {
        return Err((
            StatusCode::FORBIDDEN,
            "an unscoped administrator token is required".into(),
        ));
    }
    Ok(principal)
}

fn store_error(error: StoreError) -> ApiError {
    tracing::error!(%error, "console storage operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "console storage operation failed".into(),
    )
}

#[derive(Serialize)]
struct SecretSlotStatus {
    slot: String,
    source: String,
    scope: Option<SecretScope>,
    name: Option<String>,
    field: String,
    configured: bool,
    updated_at: Option<i64>,
    can_edit: bool,
}

#[derive(Serialize)]
struct PlatformOverview {
    id: String,
    provider_id: String,
    provider_name: String,
    provider_icon: Option<String>,
    preset: Option<String>,
    custom_rule_count: usize,
    inject_hosts: Vec<String>,
    server_tunnel_hosts: Vec<String>,
    secrets: Vec<SecretSlotStatus>,
}

#[derive(Serialize)]
struct ProfileOverview {
    name: String,
    description: String,
    allowed_groups: Vec<String>,
    allowed_users: Vec<String>,
    fallback: DefaultRouteAction,
    can_issue_keys: bool,
    revision: String,
    updated_by: String,
    updated_at: i64,
    platforms: Vec<PlatformOverview>,
}

#[derive(Serialize)]
struct ConsoleContext {
    email: String,
    display_name: String,
    admin: bool,
    encryption_ready: bool,
    providers: Vec<ProviderCatalogEntry>,
    profiles: Vec<ProfileOverview>,
    shared_secrets: Vec<SecretMeta>,
}

fn build_secret_statuses(
    platform: &cx_plugin::ResolvedPlatform,
    secret_index: &HashMap<(SecretScope, String), i64>,
    admin: bool,
    can_write_personal: bool,
) -> Vec<SecretSlotStatus> {
    let mut slots: Vec<String> = platform.secret_fields.clone();
    for slot in platform.secret_bindings.keys() {
        if !slots.contains(slot) {
            slots.push(slot.clone());
        }
    }

    slots
        .into_iter()
        .map(|slot| match platform.secret_bindings.get(&slot) {
            Some(SecretBinding::Db { scope, name, field }) => {
                let updated_at = secret_index.get(&(*scope, name.clone())).copied();
                let can_edit = match scope {
                    SecretScope::Shared => admin,
                    SecretScope::Personal => can_write_personal,
                };
                SecretSlotStatus {
                    field: field.clone().unwrap_or_else(|| slot.clone()),
                    slot,
                    source: "db".into(),
                    scope: Some(*scope),
                    name: Some(name.clone()),
                    configured: updated_at.is_some(),
                    updated_at,
                    can_edit,
                }
            }
            Some(SecretBinding::Env { var }) => SecretSlotStatus {
                field: slot.clone(),
                slot,
                source: "env".into(),
                scope: None,
                name: Some(var.clone()),
                configured: std::env::var(var).is_ok(),
                updated_at: None,
                can_edit: false,
            },
            Some(SecretBinding::Inline { .. }) => SecretSlotStatus {
                field: slot.clone(),
                slot,
                source: "inline".into(),
                scope: None,
                name: None,
                configured: true,
                updated_at: None,
                can_edit: false,
            },
            None => SecretSlotStatus {
                field: slot.clone(),
                slot,
                source: "unconfigured".into(),
                scope: None,
                name: None,
                configured: false,
                updated_at: None,
                can_edit: false,
            },
        })
        .collect()
}

async fn context(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
) -> Result<Json<ConsoleContext>, ApiError> {
    let principal = authenticate_request(&state, &headers).await?;
    let admin = is_admin(&state, &principal);
    let can_write_personal = principal.allowed_profiles.is_none();

    let stored_list = state.store.list_profiles().await.map_err(store_error)?;
    let secret_meta = state
        .store
        .list_secret_metadata(&principal.user.id)
        .await
        .map_err(store_error)?;
    let secret_index: HashMap<(SecretScope, String), i64> = secret_meta
        .iter()
        .map(|m| ((m.scope, m.name.clone()), m.updated_at))
        .collect();

    let shared_secrets: Vec<SecretMeta> = if admin {
        secret_meta
            .into_iter()
            .filter(|m| m.scope == SecretScope::Shared)
            .collect()
    } else {
        Vec::new()
    };

    let resolved_map = state.profiles.load();
    let mut profiles = Vec::new();

    for stored in stored_list {
        let Some(resolved) = resolved_map.get(&stored.spec.name) else {
            continue;
        };
        let permitted = resolved.user_has_access(
            &principal.user.id,
            &principal.user.email,
            &principal.user.groups,
        ) && principal
            .allowed_profiles
            .as_ref()
            .is_none_or(|p| p.contains(&resolved.name));
        if !admin && !permitted {
            continue;
        }
        let platforms = resolved
            .platforms
            .values()
            .map(|plat| PlatformOverview {
                id: plat.id.clone(),
                provider_id: plat.provider_id.clone(),
                provider_name: plat.provider_name.clone(),
                provider_icon: plat.provider_icon.clone(),
                preset: plat.preset.clone(),
                custom_rule_count: plat.custom_rules.len(),
                inject_hosts: plat.inject_hosts.clone(),
                server_tunnel_hosts: plat.server_tunnel_hosts.clone(),
                secrets: build_secret_statuses(
                    plat,
                    &secret_index,
                    admin,
                    can_write_personal && permitted,
                ),
            })
            .collect();

        profiles.push(ProfileOverview {
            name: resolved.name.clone(),
            description: resolved.description.clone(),
            allowed_groups: resolved.allowed_groups.clone(),
            allowed_users: resolved.allowed_users.clone(),
            fallback: resolved.routing.default_action,
            can_issue_keys: permitted,
            revision: stored.revision,
            updated_by: stored.updated_by,
            updated_at: stored.updated_at,
            platforms,
        });
    }

    Ok(Json(ConsoleContext {
        email: principal.user.email,
        display_name: principal.user.display_name,
        admin,
        encryption_ready: state.store.has_master_key(),
        providers: state.registry.list_provider_catalog(),
        profiles,
        shared_secrets,
    }))
}

#[derive(Serialize)]
struct PlatformDetail {
    spec: PlatformSpec,
    provider_name: String,
    provider_icon: Option<String>,
    inject_hosts: Vec<String>,
    server_tunnel_hosts: Vec<String>,
    preset_rules: Vec<PolicyRuleConfig>,
    secret_fields: Vec<String>,
    secrets: Vec<SecretSlotStatus>,
}

#[derive(Serialize)]
struct ProfileDetail {
    name: String,
    description: String,
    allowed_groups: Vec<String>,
    allowed_users: Vec<String>,
    deny_hosts: Vec<String>,
    fallback: DefaultRouteAction,
    can_issue_keys: bool,
    revision: String,
    updated_by: String,
    updated_at: i64,
    created_at: i64,
    platforms: Vec<PlatformDetail>,
}

fn build_profile_detail(
    stored: StoredProfile,
    resolved: &ResolvedProfile,
    secret_index: &HashMap<(SecretScope, String), i64>,
    admin: bool,
    permitted: bool,
    can_write_personal: bool,
) -> ProfileDetail {
    let spec_by_id: BTreeMap<String, PlatformSpec> = stored
        .spec
        .platforms
        .into_iter()
        .map(|p| (p.id.clone(), p))
        .collect();

    let platforms = resolved
        .platforms
        .values()
        .filter_map(|plat| {
            let spec = spec_by_id.get(&plat.id)?.clone();
            Some(PlatformDetail {
                spec,
                provider_name: plat.provider_name.clone(),
                provider_icon: plat.provider_icon.clone(),
                inject_hosts: plat.inject_hosts.clone(),
                server_tunnel_hosts: plat.server_tunnel_hosts.clone(),
                preset_rules: plat.preset_rules.clone(),
                secret_fields: plat.secret_fields.clone(),
                secrets: build_secret_statuses(
                    plat,
                    secret_index,
                    admin,
                    can_write_personal && permitted,
                ),
            })
        })
        .collect();

    ProfileDetail {
        name: stored.spec.name,
        description: stored.spec.description,
        allowed_groups: stored.spec.allowed_groups,
        allowed_users: stored.spec.allowed_users,
        deny_hosts: stored.spec.deny_hosts,
        fallback: stored.spec.fallback,
        can_issue_keys: permitted,
        revision: stored.revision,
        updated_by: stored.updated_by,
        updated_at: stored.updated_at,
        created_at: stored.created_at,
        platforms,
    }
}

async fn get_profile(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Path(profile_name): Path<String>,
) -> Result<Json<ProfileDetail>, ApiError> {
    let principal = authenticate_request(&state, &headers).await?;
    let admin = is_admin(&state, &principal);
    let stored = state
        .store
        .get_profile(&profile_name)
        .await
        .map_err(store_error)?
        .ok_or((StatusCode::NOT_FOUND, "profile not found".into()))?;
    let resolved = state
        .profiles
        .load()
        .get(&profile_name)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "profile not found".into()))?;

    let permitted = resolved.user_has_access(
        &principal.user.id,
        &principal.user.email,
        &principal.user.groups,
    ) && principal
        .allowed_profiles
        .as_ref()
        .is_none_or(|p| p.contains(&resolved.name));
    if !admin && !permitted {
        return Err((StatusCode::FORBIDDEN, "forbidden for this profile".into()));
    }

    let secret_meta = state
        .store
        .list_secret_metadata(&principal.user.id)
        .await
        .map_err(store_error)?;
    let secret_index: HashMap<(SecretScope, String), i64> = secret_meta
        .into_iter()
        .map(|m| ((m.scope, m.name), m.updated_at))
        .collect();

    Ok(Json(build_profile_detail(
        stored,
        &resolved,
        &secret_index,
        admin,
        permitted,
        principal.allowed_profiles.is_none(),
    )))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProfileInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    allowed_groups: Vec<String>,
    #[serde(default)]
    allowed_users: Vec<String>,
    #[serde(default)]
    deny_hosts: Vec<String>,
    #[serde(default)]
    fallback: DefaultRouteAction,
    #[serde(default)]
    platforms: Vec<PlatformSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProfileInput {
    revision: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    allowed_groups: Vec<String>,
    #[serde(default)]
    allowed_users: Vec<String>,
    #[serde(default)]
    deny_hosts: Vec<String>,
    #[serde(default)]
    fallback: DefaultRouteAction,
    #[serde(default)]
    platforms: Vec<PlatformSpec>,
}

fn validate_profile_limits(spec: &ProfileSpec) -> Result<(), ApiError> {
    if spec.description.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            "profile description exceeds 512 characters".into(),
        ));
    }
    if spec.platforms.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "profile exceeds maximum of 64 attached platforms".into(),
        ));
    }
    for plat in &spec.platforms {
        if plat.rules.len() > 250
            || plat.rules.iter().any(|rule| {
                [&rule.hosts, &rule.paths, &rule.methods]
                    .iter()
                    .any(|parts| {
                        parts.len() > 100
                            || parts
                                .iter()
                                .any(|value| value.len() > 1024 || value.trim().is_empty())
                    })
            })
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "platform '{}' policy exceeds rule limits or contains empty match values",
                    plat.id
                ),
            ));
        }
        for (slot, binding) in &plat.secrets {
            if let SecretBinding::Db { name, .. } = binding {
                if name.trim().is_empty() || name.len() > 128 {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "platform '{}' secret '{}' must have a non-empty name (<=128 chars)",
                            plat.id, slot
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn create_profile(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Json(input): Json<CreateProfileInput>,
) -> Result<(StatusCode, Json<ProfileDetail>), ApiError> {
    let principal = require_admin(&state, &headers).await?;
    let spec = ProfileSpec {
        name: input.name.trim().to_string(),
        description: input.description.trim().to_string(),
        allowed_groups: input
            .allowed_groups
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        allowed_users: input
            .allowed_users
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        deny_hosts: input
            .deny_hosts
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        fallback: input.fallback,
        platforms: input.platforms,
    };
    validate_profile_limits(&spec)?;
    let resolved = state
        .registry
        .resolve_profile(&spec)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;

    let revision = Uuid::new_v4().to_string();
    let actor = principal.user.email.clone();
    let uid = principal.user.id.clone();
    let groups = principal.user.groups.clone();

    let (stored, resolved_arc) = {
        let _guard = state.profile_write.lock().await;
        let Some(stored) = state
            .store
            .create_profile(&spec, &revision, &actor)
            .await
            .map_err(store_error)?
        else {
            return Err((
                StatusCode::CONFLICT,
                format!("profile '{}' already exists", spec.name),
            ));
        };
        let resolved_arc = Arc::new(resolved);
        let mut next = (**state.profiles.load()).clone();
        next.insert(spec.name.clone(), Arc::clone(&resolved_arc));
        state.profiles.store(Arc::new(next));
        (stored, resolved_arc)
    };

    let secret_meta = state
        .store
        .list_secret_metadata(&uid)
        .await
        .map_err(store_error)?;
    let secret_index: HashMap<(SecretScope, String), i64> = secret_meta
        .into_iter()
        .map(|m| ((m.scope, m.name), m.updated_at))
        .collect();
    let permitted = resolved_arc.user_has_access(&uid, &actor, &groups);

    Ok((
        StatusCode::CREATED,
        Json(build_profile_detail(
            stored,
            &resolved_arc,
            &secret_index,
            true,
            permitted,
            true,
        )),
    ))
}

async fn update_profile(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Path(profile_name): Path<String>,
    Json(input): Json<UpdateProfileInput>,
) -> Result<Json<ProfileDetail>, ApiError> {
    let principal = require_admin(&state, &headers).await?;
    let spec = ProfileSpec {
        name: profile_name.clone(),
        description: input.description.trim().to_string(),
        allowed_groups: input
            .allowed_groups
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        allowed_users: input
            .allowed_users
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        deny_hosts: input
            .deny_hosts
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        fallback: input.fallback,
        platforms: input.platforms,
    };
    validate_profile_limits(&spec)?;
    let resolved = state
        .registry
        .resolve_profile(&spec)
        .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;

    let new_revision = Uuid::new_v4().to_string();
    let actor = principal.user.email.clone();
    let uid = principal.user.id.clone();
    let groups = principal.user.groups.clone();

    let (stored, resolved_arc) = {
        let _guard = state.profile_write.lock().await;
        if state
            .store
            .get_profile(&profile_name)
            .await
            .map_err(store_error)?
            .is_none()
        {
            return Err((StatusCode::NOT_FOUND, "profile not found".into()));
        }
        let Some(stored) = state
            .store
            .update_profile(&spec, &input.revision, &new_revision, &actor)
            .await
            .map_err(store_error)?
        else {
            return Err((
                StatusCode::CONFLICT,
                "profile changed since it was opened. Reload and try again.".into(),
            ));
        };
        let resolved_arc = Arc::new(resolved);
        let mut next = (**state.profiles.load()).clone();
        next.insert(profile_name, Arc::clone(&resolved_arc));
        state.profiles.store(Arc::new(next));
        (stored, resolved_arc)
    };

    let secret_meta = state
        .store
        .list_secret_metadata(&uid)
        .await
        .map_err(store_error)?;
    let secret_index: HashMap<(SecretScope, String), i64> = secret_meta
        .into_iter()
        .map(|m| ((m.scope, m.name), m.updated_at))
        .collect();
    let permitted = resolved_arc.user_has_access(&uid, &actor, &groups);

    Ok(Json(build_profile_detail(
        stored,
        &resolved_arc,
        &secret_index,
        true,
        permitted,
        true,
    )))
}

async fn delete_profile(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Path(profile_name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let _ = require_admin(&state, &headers).await?;
    let _guard = state.profile_write.lock().await;
    let deleted = state
        .store
        .delete_profile(&profile_name)
        .await
        .map_err(store_error)?;
    if !deleted {
        return Err((StatusCode::NOT_FOUND, "profile not found".into()));
    }
    let mut next = (**state.profiles.load()).clone();
    next.remove(&profile_name);
    state.profiles.store(Arc::new(next));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AuditQuery {
    profile: Option<String>,
    platform: Option<String>,
    decision: Option<String>,
    search: Option<String>,
    before: Option<i64>,
}

#[derive(Serialize)]
struct AuditPage {
    events: Vec<AuditEntry>,
    next: Option<i64>,
}

async fn audit(
    State(state): State<Arc<ControlPlaneState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, ApiError> {
    const PAGE_SIZE: usize = 25;
    let principal = authenticate_request(&state, &headers).await?;
    let user_id = (!is_admin(&state, &principal)).then_some(principal.user.id);
    let search = query
        .search
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let platform = query
        .platform
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if search.as_ref().is_some_and(|value| value.len() > 256)
        || query.before.is_some_and(|value| value < 1)
    {
        return Err((StatusCode::BAD_REQUEST, "invalid audit filter".into()));
    }
    let mut events = state
        .store
        .list_audit(AuditFilter {
            user_id,
            allowed_profiles: principal.allowed_profiles,
            profile: query.profile,
            platform,
            decision: query.decision,
            search,
            before: query.before,
            limit: PAGE_SIZE as i64 + 1,
        })
        .await
        .map_err(store_error)?;
    let next = (events.len() > PAGE_SIZE).then(|| events[PAGE_SIZE - 1].id);
    events.truncate(PAGE_SIZE);
    Ok(Json(AuditPage { events, next }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use arc_swap::ArcSwap;
    use axum::extract::State as AxumState;
    use axum::routing::{get as axum_get, post as axum_post};
    use axum::{Form, Json as AxumJson, Router as AxumRouter};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use cx_crypto::{EnvelopeCipher, SessionSigner};
    use cx_plugin::{HostPatternValidator, ProviderRegistry};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;

    use crate::config::OidcConfig;
    use crate::controlplane::{ControlPlaneState, build_router};
    use crate::oidc::OidcClient;
    use crate::store::{MemoryStore, ServerStore};

    const TEST_EC_PRIVATE_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgl4P92xktvaTF0Ay9
8/3nP2u24NHwzwLVDDvjgDy92kihRANCAASQES5RikN/eB2ytkdYfWsbTWiqQtGc
r49a8s8FnaNbeuNPfdPIBXSLROjI7BWGVChJmETldRIkW5Lu3Tm8C6IG
-----END PRIVATE KEY-----";
    const TEST_EC_X: &str = "kBEuUYpDf3gdsrZHWH1rG01oqkLRnK-PWvLPBZ2jW3o";
    const TEST_EC_Y: &str = "409908gFdItE6MjsFYZUKEmYROV1EiRbku7dObwLogY";

    #[derive(Clone)]
    struct MockIdpState {
        issuer: String,
        expected_nonce: Arc<Mutex<String>>,
        expected_challenge: Arc<Mutex<String>>,
    }

    async fn start_mock_oidc_provider() -> (String, Arc<Mutex<String>>, Arc<Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let expected_nonce = Arc::new(Mutex::new(String::new()));
        let expected_challenge = Arc::new(Mutex::new(String::new()));
        let state = MockIdpState {
            issuer: issuer.clone(),
            expected_nonce: Arc::clone(&expected_nonce),
            expected_challenge: Arc::clone(&expected_challenge),
        };

        let app = AxumRouter::new()
            .route(
                "/.well-known/openid-configuration",
                axum_get(|AxumState(s): AxumState<MockIdpState>| async move {
                    AxumJson(serde_json::json!({
                        "issuer": s.issuer,
                        "authorization_endpoint": format!("{}/authorize", s.issuer),
                        "token_endpoint": format!("{}/token", s.issuer),
                        "jwks_uri": format!("{}/jwks.json", s.issuer),
                    }))
                }),
            )
            .route(
                "/jwks.json",
                axum_get(|| async {
                    AxumJson(serde_json::json!({
                        "keys": [{
                            "kty": "EC",
                            "crv": "P-256",
                            "kid": "test-es256",
                            "use": "sig",
                            "alg": "ES256",
                            "x": TEST_EC_X,
                            "y": TEST_EC_Y
                        }]
                    }))
                }),
            )
            .route(
                "/token",
                axum_post(
                    |AxumState(s): AxumState<MockIdpState>,
                     Form(form): Form<BTreeMap<String, String>>| async move {
                        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                        let computed_challenge =
                            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                        assert_eq!(computed_challenge, *s.expected_challenge.lock().unwrap());
                        assert_eq!(form.get("code").map(String::as_str), Some("mock-auth-code"));
                        let nonce = s.expected_nonce.lock().unwrap().clone();
                        let now = chrono::Utc::now().timestamp();
                        let claims = serde_json::json!({
                            "iss": s.issuer,
                            "sub": "user-oidc-42",
                            "aud": "cx-web-test",
                            "exp": now + 600,
                            "iat": now,
                            "nonce": nonce,
                            "email": "oidc-admin@example.com",
                            "name": "OIDC Admin",
                            "groups": ["cx-admins", "eng"]
                        });
                        let mut header = Header::new(Algorithm::ES256);
                        header.kid = Some("test-es256".into());
                        let key = EncodingKey::from_ec_pem(TEST_EC_PRIVATE_PEM.as_bytes()).unwrap();
                        let id_token = encode(&header, &claims, &key).unwrap();
                        AxumJson(serde_json::json!({ "id_token": id_token }))
                    },
                ),
            )
            .with_state(state);

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (issuer, expected_nonce, expected_challenge)
    }

    fn cookie_pair_from_set_cookie(
        headers: &reqwest::header::HeaderMap,
        name: &str,
    ) -> Option<String> {
        for val in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(s) = val.to_str() else { continue };
            if let Some(first) = s.split(';').next() {
                if let Some((k, v)) = first.split_once('=') {
                    if k.trim() == name {
                        return Some(format!("{}={}", k.trim(), v.trim()));
                    }
                }
            }
        }
        None
    }

    #[tokio::test]
    async fn web_console_oidc_login_csrf_protection_and_logout_flow() {
        let (issuer, expected_nonce, expected_challenge) = start_mock_oidc_provider().await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let external_url = format!("http://{server_addr}");

        let oidc_cfg = OidcConfig {
            issuer: issuer.clone(),
            client_id: "cx-web-test".into(),
            client_secret_env: None,
            client_secret_inline: Some("mock-secret".into()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            groups_claim: "groups".into(),
            admin_groups: vec!["cx-admins".into()],
        };
        let oidc = OidcClient::new(oidc_cfg, &external_url);
        let cipher = EnvelopeCipher::from_base64(
            &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        )
        .unwrap();
        let store: Arc<dyn ServerStore> = Arc::new(MemoryStore::new(Some(cipher)));
        let registry = ProviderRegistry::new(
            None,
            true,
            HostPatternValidator {
                allow_private_targets: true,
                allow_apex_wildcard: false,
            },
        )
        .unwrap();

        let state = Arc::new(ControlPlaneState {
            external_url: external_url.clone(),
            quic_public_addr: "127.0.0.1:8443".into(),
            quic_server_name: "localhost".into(),
            session_ttl_secs: 600,
            trusted_proxies: vec![],
            admin_groups: vec!["cx-admins".into()],
            signer: SessionSigner::generate(),
            store,
            oidc: Some(oidc),
            profiles: Arc::new(ArcSwap::from_pointee(BTreeMap::new())),
            registry,
            profile_write: tokio::sync::Mutex::new(()),
        });

        let app = build_router(state);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        // 1. Public auth config reports OIDC enabled
        let cfg: serde_json::Value = client
            .get(format!("{external_url}/v1/console/auth-config"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(cfg["oidc_enabled"], true);
        assert!(cfg.get("oidc_issuer").is_none());
        assert_eq!(cfg["session_active"], false);

        // 2. Start OIDC login -> redirects to IdP authorize endpoint and sets HttpOnly tx cookie
        let start_resp = client
            .get(format!("{external_url}/v1/console/auth/oidc/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(start_resp.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        let tx_cookie = cookie_pair_from_set_cookie(start_resp.headers(), "cx_oidc_tx")
            .expect("expected cx_oidc_tx cookie");
        let location = start_resp
            .headers()
            .get(reqwest::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        let auth_url = reqwest::Url::parse(location).unwrap();
        let params: BTreeMap<String, String> = auth_url.query_pairs().into_owned().collect();
        let oidc_state = params.get("state").unwrap().clone();
        assert!(oidc_state.starts_with("cxweb_"));
        *expected_nonce.lock().unwrap() = params.get("nonce").unwrap().clone();
        *expected_challenge.lock().unwrap() = params.get("code_challenge").unwrap().clone();

        // 3. Login CSRF check: callback without cx_oidc_tx cookie must fail cleanly
        let csrf_cb = client
            .get(format!(
                "{external_url}/v1/auth/oidc/callback?code=mock-auth-code&state={oidc_state}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(csrf_cb.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(
            csrf_cb.headers().get(reqwest::header::LOCATION).unwrap(),
            "/ui/?auth_error=oidc_invalid_session"
        );
        assert!(cookie_pair_from_set_cookie(csrf_cb.headers(), "cx_console_session").is_none());

        // 4. Valid callback with cx_oidc_tx cookie -> sets HttpOnly cx_console_session & redirects to /ui/
        let ok_cb = client
            .get(format!(
                "{external_url}/v1/auth/oidc/callback?code=mock-auth-code&state={oidc_state}"
            ))
            .header(reqwest::header::COOKIE, &tx_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(ok_cb.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(
            ok_cb.headers().get(reqwest::header::LOCATION).unwrap(),
            "/ui/"
        );
        let session_cookie = cookie_pair_from_set_cookie(ok_cb.headers(), "cx_console_session")
            .expect("expected cx_console_session cookie");
        assert!(session_cookie.starts_with("cx_console_session=cx_web_"));

        // 5. Replay protection
        let replay_cb = client
            .get(format!(
                "{external_url}/v1/auth/oidc/callback?code=mock-auth-code&state={oidc_state}"
            ))
            .header(reqwest::header::COOKIE, &tx_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(replay_cb.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(
            replay_cb.headers().get(reqwest::header::LOCATION).unwrap(),
            "/ui/?auth_error=oidc_expired"
        );
        assert!(cookie_pair_from_set_cookie(replay_cb.headers(), "cx_console_session").is_none());

        // 6. Cookie auth without X-CX-Console CSRF header must be rejected (403)
        let missing_csrf = client
            .get(format!("{external_url}/v1/console"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), reqwest::StatusCode::FORBIDDEN);

        // 7. Cross-site Fetch with cookie must be rejected (403)
        let cross_site = client
            .get(format!("{external_url}/v1/console"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .header("Sec-Fetch-Site", "cross-site")
            .send()
            .await
            .unwrap();
        assert_eq!(cross_site.status(), reqwest::StatusCode::FORBIDDEN);

        // 8. Create a multi-platform DB Profile (github + openai + two generic-http instances)
        let create_resp = client
            .post(format!("{external_url}/v1/console/profiles"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .json(&serde_json::json!({
                "name": "coding-agent",
                "description": "Multi-platform agent profile",
                "allowed_groups": ["eng", "cx-admins"],
                "fallback": "client_passthrough",
                "platforms": [
                    {
                        "id": "github",
                        "provider_id": "github",
                        "preset": "readonly",
                        "secrets": {
                            "token": { "source": "db", "scope": "shared", "name": "coding-agent/github" }
                        }
                    },
                    {
                        "id": "openai",
                        "provider_id": "openai",
                        "preset": "full",
                        "secrets": {
                            "api_key": { "source": "db", "scope": "personal", "name": "openai" }
                        }
                    },
                    {
                        "id": "jira",
                        "provider_id": "generic-http",
                        "params": { "host": "jira.example.com", "env_var": "JIRA_TOKEN" },
                        "preset": "full",
                        "secrets": {
                            "token": { "source": "db", "scope": "shared", "name": "jira-shared" }
                        }
                    },
                    {
                        "id": "billing",
                        "provider_id": "generic-http",
                        "params": { "host": "billing.example.com", "env_var": "BILLING_TOKEN" },
                        "preset": "full"
                    }
                ]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(create_resp.status(), reqwest::StatusCode::CREATED);
        let created: serde_json::Value = create_resp.json().await.unwrap();
        assert_eq!(created["name"], "coding-agent");
        assert_eq!(created["platforms"].as_array().unwrap().len(), 4);
        let rev1 = created["revision"].as_str().unwrap().to_string();

        // 9. Save shared secret and verify secret status flips to configured = true without leaking plaintext
        let save_secret = client
            .post(format!("{external_url}/v1/secrets"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .json(&serde_json::json!({
                "name": "coding-agent/github",
                "scope": "shared",
                "fields": { "token": "ghp_super_secret" }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(save_secret.status(), reqwest::StatusCode::NO_CONTENT);

        let console_ctx: serde_json::Value = client
            .get(format!("{external_url}/v1/console"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(console_ctx["email"], "oidc-admin@example.com");
        assert_eq!(console_ctx["admin"], true);
        let gh_plat = console_ctx["profiles"][0]["platforms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == "github")
            .unwrap();
        assert_eq!(gh_plat["secrets"][0]["configured"], true);
        assert!(!console_ctx.to_string().contains("ghp_super_secret"));

        // 10. Stale revision update returns 409; valid revision update succeeds; delete removes profile
        let stale_put = client
            .put(format!("{external_url}/v1/console/profiles/coding-agent"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .json(&serde_json::json!({
                "revision": "wrong-rev",
                "description": "Updated",
                "allowed_groups": ["eng"],
                "platforms": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(stale_put.status(), reqwest::StatusCode::CONFLICT);

        let ok_put = client
            .put(format!("{external_url}/v1/console/profiles/coding-agent"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .json(&serde_json::json!({
                "revision": rev1,
                "description": "Updated desc",
                "allowed_groups": ["eng", "cx-admins"],
                "platforms": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(ok_put.status(), reqwest::StatusCode::OK);

        let del_resp = client
            .delete(format!("{external_url}/v1/console/profiles/coding-agent"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(del_resp.status(), reqwest::StatusCode::NO_CONTENT);

        // 11. Logout revokes token in store and clears session cookie
        let logout_resp = client
            .post(format!("{external_url}/v1/console/auth/logout"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(logout_resp.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(
            cookie_pair_from_set_cookie(logout_resp.headers(), "cx_console_session").as_deref(),
            Some("cx_console_session=")
        );

        let after_logout = client
            .get(format!("{external_url}/v1/console"))
            .header(reqwest::header::COOKIE, &session_cookie)
            .header("X-CX-Console", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(after_logout.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}
