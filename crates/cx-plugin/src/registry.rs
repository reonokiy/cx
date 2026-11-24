use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use cx_crypto::{VirtualKeySpec, VirtualKeySpecError};
use cx_protocol::{
    ClientLaunchSpec, DefaultRouteAction, GitRewriteRule, RoutingPolicy, host_matches_pattern,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::injector::{
    AuthInjector, BasicAuthInjector, BearerHeaderInjector, HeaderTokenInjector,
};
use crate::manifest::{
    BUILTIN_GENERIC_HTTP_TOML, BUILTIN_GITHUB_TOML, BUILTIN_OPENAI_TOML, InjectMode,
    InjectRuleConfig, PolicyRuleConfig, ProviderManifest, render_client_template, render_params,
};
use crate::policy::{CompiledPolicy, PolicyCompileError};
use crate::validator::{
    HostPatternValidator, ValidationError, pattern_is_subset_of, patterns_overlap,
};

/// Built-in fallback HTTP provider that may be attached multiple times per profile with distinct IDs.
pub const GENERIC_HTTP_PROVIDER_ID: &str = "generic-http";

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error in {0}: {1}")]
    Toml(String, String),
    #[error("invalid identifier '{0}': must be 1..=64 chars of [a-z0-9._-], starting with [a-z0-9]")]
    InvalidIdentifier(String),
    #[error("provider '{0}' not found")]
    NotFound(String),
    #[error("duplicate platform id '{0}' in profile")]
    DuplicatePlatformId(String),
    #[error("provider '{0}' can only be attached once per profile (only '{GENERIC_HTTP_PROVIDER_ID}' supports multiple entries)")]
    DuplicateNamedProvider(String),
    #[error("named provider '{0}' must use platform id '{0}' (got '{1}')")]
    NamedProviderIdMismatch(String, String),
    #[error("inject host '{host}' conflicts between platforms '{first_platform}' and '{second_platform}'")]
    HostConflict {
        host: String,
        first_platform: String,
        second_platform: String,
    },
    #[error("environment variable '{env_var}' conflicts between platforms '{first_platform}' and '{second_platform}'")]
    EnvConflict {
        env_var: String,
        first_platform: String,
        second_platform: String,
    },
    #[error("git host '{host}' conflicts between platforms '{first_platform}' and '{second_platform}'")]
    GitHostConflict {
        host: String,
        first_platform: String,
        second_platform: String,
    },
    #[error("provider '{0}' missing required parameter '{1}'")]
    MissingParam(String, String),
    #[error("provider '{0}' unknown policy preset '{1}'")]
    UnknownPreset(String, String),
    #[error("insecure http scheme disallowed for injector '{0}'")]
    InsecureScheme(String),
    #[error(transparent)]
    VirtualKey(#[from] VirtualKeySpecError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Policy(#[from] PolicyCompileError),
}

pub fn validate_identifier(value: &str) -> Result<(), PluginError> {
    if value.is_empty() || value.len() > 64 {
        return Err(PluginError::InvalidIdentifier(value.into()));
    }
    let bytes = value.as_bytes();
    if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return Err(PluginError::InvalidIdentifier(value.into()));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(PluginError::InvalidIdentifier(value.into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScope {
    #[default]
    Shared,
    Personal,
}

/// Strongly-typed secret source binding configured per secret slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SecretBinding {
    /// Read directly from a server environment variable.
    Env { var: String },
    /// Read from the server's envelope-encrypted database.
    Db {
        #[serde(default)]
        scope: SecretScope,
        name: String,
        /// Optional field key inside the stored secret object (defaults to the slot name).
        #[serde(default)]
        field: Option<String>,
    },
    /// Literal value (intended for local dev / automated tests only).
    Inline { value: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformRoutingOverride {
    #[serde(default)]
    pub inject_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub passthrough_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub passthrough_ports: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSpec {
    /// Unique platform binding ID within the profile.
    /// Non-`generic-http` providers must use `id == provider_id`.
    /// `generic-http` allows custom IDs (e.g., `internal-api`, `jira`) for multiple entries.
    pub id: String,
    pub provider_id: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    /// Secret slot -> structured binding.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretBinding>,
    #[serde(default)]
    pub virtual_key_override: Option<VirtualKeySpec>,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
    #[serde(default)]
    pub routing: PlatformRoutingOverride,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub fallback: DefaultRouteAction,
    #[serde(default)]
    pub platforms: Vec<PlatformSpec>,
}

pub struct ResolvedPlatform {
    pub id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_icon: Option<String>,
    pub resolved_params: BTreeMap<String, String>,
    pub secret_bindings: BTreeMap<String, SecretBinding>,
    pub secret_fields: Vec<String>,
    pub virtual_key: VirtualKeySpec,
    pub inject_hosts: Vec<String>,
    pub server_tunnel_hosts: Vec<String>,
    pub server_tunnel_ports: Vec<u16>,
    pub server_http_passthrough_hosts: Vec<String>,
    pub env_template: BTreeMap<String, String>,
    pub git_template: Vec<(String, Vec<String>, String)>,
    pub injectors: Vec<Arc<dyn AuthInjector>>,
    pub policy: CompiledPolicy,
    pub preset: Option<String>,
    pub preset_rules: Vec<PolicyRuleConfig>,
    pub custom_rules: Vec<PolicyRuleConfig>,
}

impl ResolvedPlatform {
    pub fn matches_inject_host(&self, host: &str) -> bool {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        self.inject_hosts
            .iter()
            .any(|p| host_matches_pattern(&host_lc, p))
    }

    pub fn matches_tunnel_host(&self, host: &str, port: u16) -> bool {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        let port_ok =
            self.server_tunnel_ports.is_empty() || self.server_tunnel_ports.contains(&port);
        port_ok
            && self
                .server_tunnel_hosts
                .iter()
                .any(|p| host_matches_pattern(&host_lc, p))
    }

    pub fn matches_http_passthrough_host(&self, host: &str) -> bool {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        self.server_http_passthrough_hosts
            .iter()
            .any(|p| host_matches_pattern(&host_lc, p))
    }
}

pub struct ResolvedProfile {
    pub name: String,
    pub description: String,
    pub platforms: BTreeMap<String, ResolvedPlatform>,
    pub routing: RoutingPolicy,
    pub allowed_groups: Vec<String>,
    pub allowed_users: Vec<String>,
}

impl ResolvedProfile {
    /// Generate a fresh per-platform ephemeral virtual key for a new QUIC session.
    pub fn generate_ephemeral_virtual_keys(&self) -> BTreeMap<String, String> {
        self.platforms
            .iter()
            .map(|(id, p)| (id.clone(), p.virtual_key.generate()))
            .collect()
    }

    /// Merge all attached platforms' client launch instructions using each platform's virtual key.
    pub fn build_client_launch_spec(
        &self,
        virtual_keys: &BTreeMap<String, String>,
    ) -> ClientLaunchSpec {
        let mut env_inject = BTreeMap::new();
        let mut git_rewrites = Vec::new();

        for (id, platform) in &self.platforms {
            let Some(vk) = virtual_keys.get(id) else {
                continue;
            };
            for (raw_k, raw_v) in &platform.env_template {
                let k = render_params(raw_k, &platform.resolved_params);
                let v = render_client_template(raw_v, &platform.resolved_params, vk);
                env_inject.insert(k, v);
            }
            for (host, from, user) in &platform.git_template {
                git_rewrites.push(GitRewriteRule {
                    host: host.clone(),
                    from: from.clone(),
                    credential_username: user.clone(),
                    virtual_key: vk.clone(),
                });
            }
        }

        ClientLaunchSpec {
            env_inject,
            git_rewrites,
        }
    }

    pub fn find_platform_for_l7_host(&self, host: &str) -> Option<&ResolvedPlatform> {
        self.platforms
            .values()
            .find(|p| p.matches_inject_host(host))
            .or_else(|| {
                self.platforms
                    .values()
                    .find(|p| p.matches_http_passthrough_host(host))
            })
    }

    pub fn find_platform_for_l4_host(&self, host: &str, port: u16) -> Option<&ResolvedPlatform> {
        self.platforms
            .values()
            .find(|p| p.matches_tunnel_host(host, port))
    }

    pub fn user_has_access(&self, user_id: &str, email: &str, groups: &[String]) -> bool {
        if self.allowed_groups.is_empty() && self.allowed_users.is_empty() {
            return false;
        }
        if self
            .allowed_users
            .iter()
            .any(|u| u == "*" || u == user_id || u.eq_ignore_ascii_case(email))
        {
            return true;
        }
        if self.allowed_groups.iter().any(|g| g == "*") {
            return true;
        }
        groups
            .iter()
            .any(|ug| self.allowed_groups.iter().any(|ag| ag == ug))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderParamInfo {
    pub name: String,
    pub required: bool,
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCatalogEntry {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
    pub version: String,
    pub description: String,
    pub allow_multiple: bool,
    pub params: Vec<ProviderParamInfo>,
    pub secret_fields: Vec<String>,
    pub default_inject_hosts: Vec<String>,
    pub default_passthrough_hosts: Vec<String>,
    pub presets: BTreeMap<String, Vec<PolicyRuleConfig>>,
}

#[derive(Default)]
struct ProviderCatalog {
    manifests: BTreeMap<String, ProviderManifest>,
}

pub struct ProviderRegistry {
    catalog: ArcSwap<ProviderCatalog>,
    providers_dir: Option<PathBuf>,
    enable_builtin: bool,
    validator: HostPatternValidator,
}

impl ProviderRegistry {
    pub fn new(
        providers_dir: Option<PathBuf>,
        enable_builtin: bool,
        validator: HostPatternValidator,
    ) -> Result<Self, PluginError> {
        let catalog = Self::load_catalog(providers_dir.as_deref(), enable_builtin)?;
        Ok(Self {
            catalog: ArcSwap::from_pointee(catalog),
            providers_dir,
            enable_builtin,
            validator,
        })
    }

    pub fn reload(&self) -> Result<usize, PluginError> {
        let next = Self::load_catalog(self.providers_dir.as_deref(), self.enable_builtin)?;
        let count = next.manifests.len();
        self.catalog.store(Arc::new(next));
        info!(provider_count = count, "reloaded provider plugins");
        Ok(count)
    }

    pub fn list_providers(&self) -> Vec<(String, String, String)> {
        let guard = self.catalog.load();
        guard
            .manifests
            .values()
            .map(|m| (m.id.clone(), m.version.clone(), m.description.clone()))
            .collect()
    }

    pub fn list_provider_catalog(&self) -> Vec<ProviderCatalogEntry> {
        let guard = self.catalog.load();
        guard
            .manifests
            .values()
            .map(|m| {
                let mut defaults = BTreeMap::new();
                let params = m
                    .params
                    .iter()
                    .map(|(name, spec)| {
                        if let Some(d) = spec.default_value() {
                            defaults.insert(name.clone(), d.to_string());
                        }
                        ProviderParamInfo {
                            name: name.clone(),
                            required: spec.is_required(),
                            default: spec.default_value().map(str::to_string),
                        }
                    })
                    .collect();

                let mut secret_fields = Vec::new();
                let mut default_inject_hosts = Vec::new();
                for inj in &m.inject {
                    if !inj.secret.is_empty() && !secret_fields.contains(&inj.secret) {
                        secret_fields.push(inj.secret.clone());
                    }
                    for h in &inj.hosts {
                        let rendered = render_params(h, &defaults);
                        if !default_inject_hosts.contains(&rendered) {
                            default_inject_hosts.push(rendered);
                        }
                    }
                }
                let default_passthrough_hosts = m
                    .passthrough
                    .hosts
                    .iter()
                    .map(|h| render_params(h, &defaults))
                    .collect();

                ProviderCatalogEntry {
                    id: m.id.clone(),
                    name: m.display_name().to_string(),
                    icon: m.icon.clone(),
                    version: m.version.clone(),
                    description: m.description.clone(),
                    allow_multiple: m.id == GENERIC_HTTP_PROVIDER_ID,
                    params,
                    secret_fields,
                    default_inject_hosts,
                    default_passthrough_hosts,
                    presets: m.presets.clone(),
                }
            })
            .collect()
    }

    pub fn validate_manifest_file(
        path: &Path,
        validator: &HostPatternValidator,
    ) -> Result<ProviderManifest, PluginError> {
        let raw = fs::read_to_string(path)?;
        let manifest = parse_manifest(&path.display().to_string(), &raw)?;
        manifest.virtual_key.validate()?;

        let mut params = BTreeMap::new();
        for (k, def) in &manifest.params {
            if let Some(d) = def.default_value() {
                params.insert(k.clone(), d.to_string());
            } else if def.is_required() {
                params.insert(k.clone(), "example.internal.invalid".to_string());
            }
        }
        for inj in &manifest.inject {
            for h in &inj.hosts {
                validator.validate_inject_host(&render_params(h, &params))?;
            }
        }
        for h in &manifest.passthrough.hosts {
            validator.validate_tunnel_host(&render_params(h, &params))?;
        }
        for rules in manifest.presets.values() {
            let rendered: Vec<PolicyRuleConfig> = rules
                .iter()
                .map(|r| render_policy_rule(r, &params))
                .collect();
            CompiledPolicy::compile(&rendered)?;
        }
        Ok(manifest)
    }

    pub fn resolve_profile(&self, spec: &ProfileSpec) -> Result<ResolvedProfile, PluginError> {
        validate_identifier(&spec.name)?;
        let catalog = self.catalog.load();

        let mut platforms: BTreeMap<String, ResolvedPlatform> = BTreeMap::new();
        let mut seen_named_providers: BTreeSet<String> = BTreeSet::new();

        // Cross-platform collision tracking
        let mut claimed_inject_hosts: Vec<(String, String)> = Vec::new(); // (host_pattern, platform_id)
        let mut claimed_env_vars: BTreeMap<String, String> = BTreeMap::new(); // env_var -> platform_id
        let mut claimed_git_hosts: BTreeMap<String, String> = BTreeMap::new(); // git_host -> platform_id

        // Aggregated 3-tier routing across all platforms
        let mut agg_inject_hosts = Vec::new();
        let mut seen_inject = BTreeSet::new();
        let mut agg_tunnel_hosts = Vec::new();
        let mut seen_tunnel = BTreeSet::new();
        let mut agg_tunnel_ports = BTreeSet::new();
        let mut agg_http_passthrough_hosts = Vec::new();
        let mut seen_http_passthrough = BTreeSet::new();

        for pspec in &spec.platforms {
            validate_identifier(&pspec.id)?;
            if platforms.contains_key(&pspec.id) {
                return Err(PluginError::DuplicatePlatformId(pspec.id.clone()));
            }
            if pspec.provider_id != GENERIC_HTTP_PROVIDER_ID {
                if pspec.id != pspec.provider_id {
                    return Err(PluginError::NamedProviderIdMismatch(
                        pspec.provider_id.clone(),
                        pspec.id.clone(),
                    ));
                }
                if !seen_named_providers.insert(pspec.provider_id.clone()) {
                    return Err(PluginError::DuplicateNamedProvider(
                        pspec.provider_id.clone(),
                    ));
                }
            }

            let manifest = catalog
                .manifests
                .get(&pspec.provider_id)
                .ok_or_else(|| PluginError::NotFound(pspec.provider_id.clone()))?;

            let resolved = self.resolve_platform(pspec, manifest)?;

            // Check cross-platform inject host overlap
            for h in &resolved.inject_hosts {
                for (existing_h, existing_platform) in &claimed_inject_hosts {
                    if patterns_overlap(h, existing_h) {
                        return Err(PluginError::HostConflict {
                            host: h.clone(),
                            first_platform: existing_platform.clone(),
                            second_platform: resolved.id.clone(),
                        });
                    }
                }
                claimed_inject_hosts.push((h.clone(), resolved.id.clone()));
                if seen_inject.insert(h.clone()) {
                    agg_inject_hosts.push(h.clone());
                }
            }

            // Check cross-platform env var collision
            for raw_k in resolved.env_template.keys() {
                let rendered_k = render_params(raw_k, &resolved.resolved_params);
                if let Some(first_platform) =
                    claimed_env_vars.insert(rendered_k.clone(), resolved.id.clone())
                {
                    return Err(PluginError::EnvConflict {
                        env_var: rendered_k,
                        first_platform,
                        second_platform: resolved.id.clone(),
                    });
                }
            }

            // Check cross-platform git rewrite host collision
            for (git_host, _, _) in &resolved.git_template {
                let lc = git_host.to_ascii_lowercase();
                if let Some(first_platform) = claimed_git_hosts.insert(lc, resolved.id.clone()) {
                    return Err(PluginError::GitHostConflict {
                        host: git_host.clone(),
                        first_platform,
                        second_platform: resolved.id.clone(),
                    });
                }
            }

            for h in &resolved.server_tunnel_hosts {
                if seen_tunnel.insert(h.clone()) {
                    agg_tunnel_hosts.push(h.clone());
                }
            }
            for port in &resolved.server_tunnel_ports {
                agg_tunnel_ports.insert(*port);
            }
            for h in &resolved.server_http_passthrough_hosts {
                if seen_http_passthrough.insert(h.clone()) {
                    agg_http_passthrough_hosts.push(h.clone());
                }
            }

            platforms.insert(resolved.id.clone(), resolved);
        }

        let mut deny_hosts = Vec::with_capacity(spec.deny_hosts.len());
        for raw in &spec.deny_hosts {
            deny_hosts.push(self.validator.validate_tunnel_host(raw)?);
        }

        let routing = RoutingPolicy {
            deny_hosts,
            inject_hosts: agg_inject_hosts,
            server_tunnel_hosts: agg_tunnel_hosts,
            server_tunnel_ports: agg_tunnel_ports.into_iter().collect(),
            server_http_passthrough_hosts: agg_http_passthrough_hosts,
            default_action: spec.fallback,
        };

        Ok(ResolvedProfile {
            name: spec.name.clone(),
            description: spec.description.clone(),
            platforms,
            routing,
            allowed_groups: spec.allowed_groups.clone(),
            allowed_users: spec.allowed_users.clone(),
        })
    }

    fn resolve_platform(
        &self,
        spec: &PlatformSpec,
        manifest: &ProviderManifest,
    ) -> Result<ResolvedPlatform, PluginError> {
        let virtual_key = spec
            .virtual_key_override
            .clone()
            .unwrap_or_else(|| manifest.virtual_key.clone());
        virtual_key.validate()?;

        let mut resolved_params = BTreeMap::new();
        for (k, def) in &manifest.params {
            if let Some(v) = spec.params.get(k).filter(|v| !v.trim().is_empty()) {
                resolved_params.insert(k.clone(), v.trim().to_string());
            } else if let Some(d) = def.default_value() {
                resolved_params.insert(k.clone(), d.to_string());
            } else if def.is_required() {
                return Err(PluginError::MissingParam(
                    spec.provider_id.clone(),
                    k.clone(),
                ));
            }
        }
        for (k, v) in &spec.params {
            if !v.trim().is_empty() {
                resolved_params
                    .entry(k.clone())
                    .or_insert_with(|| v.trim().to_string());
            }
        }

        let mut seen_inject = BTreeSet::new();
        let mut provider_inject_hosts = Vec::new();
        let mut secret_fields = Vec::new();
        for inj in &manifest.inject {
            if !inj.secret.is_empty() && !secret_fields.contains(&inj.secret) {
                secret_fields.push(inj.secret.clone());
            }
            for h in &inj.hosts {
                let validated = self
                    .validator
                    .validate_inject_host(&render_params(h, &resolved_params))?;
                if seen_inject.insert(validated.clone()) {
                    provider_inject_hosts.push(validated);
                }
            }
        }

        let provider_tunnel_hosts: Vec<String> = manifest
            .passthrough
            .hosts
            .iter()
            .map(|h| {
                self.validator
                    .validate_tunnel_host(&render_params(h, &resolved_params))
            })
            .collect::<Result<_, _>>()?;

        let inject_hosts = match &spec.routing.inject_hosts {
            Some(custom) => {
                let mut narrowed = Vec::with_capacity(custom.len());
                for h in custom {
                    let validated = self.validator.validate_inject_host(h)?;
                    if !pattern_is_subset_of(&validated, &provider_inject_hosts) {
                        return Err(ValidationError::HostOutOfPluginScope(validated).into());
                    }
                    narrowed.push(validated);
                }
                narrowed
            }
            None => provider_inject_hosts,
        };

        let server_tunnel_hosts = match &spec.routing.passthrough_hosts {
            Some(custom) => custom
                .iter()
                .map(|h| self.validator.validate_tunnel_host(h))
                .collect::<Result<Vec<_>, _>>()?,
            None => provider_tunnel_hosts,
        };

        let server_tunnel_ports = spec
            .routing
            .passthrough_ports
            .clone()
            .unwrap_or_else(|| manifest.passthrough.ports.clone());

        let server_http_passthrough_hosts = manifest
            .http_passthrough_hosts
            .iter()
            .map(|h| {
                self.validator
                    .validate_tunnel_host(&render_params(h, &resolved_params))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut injectors: Vec<Arc<dyn AuthInjector>> = Vec::new();
        for (idx, inj_cfg) in manifest.inject.iter().enumerate() {
            let injector = build_injector(
                idx,
                inj_cfg,
                &resolved_params,
                &inject_hosts,
                spec.allow_insecure_http,
            )?;
            if !injector.allowed_hosts().is_empty() {
                injectors.push(injector);
            }
        }

        let mut preset_rules = Vec::new();
        if let Some(preset_name) = &spec.preset {
            let raw_rules = manifest.presets.get(preset_name).ok_or_else(|| {
                PluginError::UnknownPreset(spec.provider_id.clone(), preset_name.clone())
            })?;
            for r in raw_rules {
                preset_rules.push(render_policy_rule(r, &resolved_params));
            }
        }
        let custom_rules: Vec<PolicyRuleConfig> = spec
            .rules
            .iter()
            .map(|r| render_policy_rule(r, &resolved_params))
            .collect();

        let mut compiled_rule_cfgs = preset_rules.clone();
        compiled_rule_cfgs.extend(custom_rules.iter().cloned());
        let policy = CompiledPolicy::compile(&compiled_rule_cfgs)?;

        let git_template = manifest
            .git
            .iter()
            .map(|g| {
                (
                    render_params(&g.host, &resolved_params),
                    g.rewrite_from
                        .iter()
                        .map(|f| render_params(f, &resolved_params))
                        .collect(),
                    g.username.clone(),
                )
            })
            .collect();

        Ok(ResolvedPlatform {
            id: spec.id.clone(),
            provider_id: manifest.id.clone(),
            provider_name: manifest.display_name().to_string(),
            provider_icon: manifest.icon.clone(),
            resolved_params,
            secret_bindings: spec.secrets.clone(),
            secret_fields,
            virtual_key,
            inject_hosts,
            server_tunnel_hosts,
            server_tunnel_ports,
            server_http_passthrough_hosts,
            env_template: manifest.env.clone(),
            git_template,
            injectors,
            policy,
            preset: spec.preset.clone(),
            preset_rules,
            custom_rules,
        })
    }

    fn load_catalog(
        providers_dir: Option<&Path>,
        enable_builtin: bool,
    ) -> Result<ProviderCatalog, PluginError> {
        let mut catalog = ProviderCatalog::default();
        if enable_builtin {
            for (name, src) in [
                ("builtin:github.toml", BUILTIN_GITHUB_TOML),
                ("builtin:openai.toml", BUILTIN_OPENAI_TOML),
                ("builtin:generic-http.toml", BUILTIN_GENERIC_HTTP_TOML),
            ] {
                let m = parse_manifest(name, src)?;
                catalog.manifests.insert(m.id.clone(), m);
            }
        }

        if let Some(dir) = providers_dir {
            if dir.exists() {
                let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
                    .filter_map(|e| e.ok().map(|de| de.path()))
                    .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
                    .collect();
                entries.sort();
                for path in entries {
                    let raw = fs::read_to_string(&path)?;
                    let m = parse_manifest(&path.display().to_string(), &raw)?;
                    catalog.manifests.insert(m.id.clone(), m);
                }
            }
        }

        Ok(catalog)
    }
}

fn sanitize_icon(source: &str, raw: Option<&str>) -> Result<Option<String>, PluginError> {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let lower = val.to_ascii_lowercase();
    if lower.starts_with("data:") {
        const MAX_DATA_URI_LEN: usize = 65_536;
        let allowed_prefix = lower.starts_with("data:image/png;base64,")
            || lower.starts_with("data:image/webp;base64,")
            || lower.starts_with("data:image/jpeg;base64,")
            || lower.starts_with("data:image/svg+xml;base64,");
        if !allowed_prefix || val.len() > MAX_DATA_URI_LEN {
            return Err(PluginError::Toml(
                source.into(),
                "icon data URI must be base64 png/webp/jpeg/svg+xml and <= 64 KiB".into(),
            ));
        }
        return Ok(Some(val.to_string()));
    }
    if lower.contains("://") || lower.starts_with("javascript:") || val.len() > 64 {
        return Err(PluginError::Toml(
            source.into(),
            "icon must be a short icon name, emoji, or base64 data:image/* URI".into(),
        ));
    }
    Ok(Some(val.to_string()))
}

fn parse_manifest(source: &str, raw: &str) -> Result<ProviderManifest, PluginError> {
    let mut manifest: ProviderManifest =
        toml::from_str(raw).map_err(|e| PluginError::Toml(source.into(), e.to_string()))?;
    manifest.virtual_key.validate()?;
    manifest.icon = sanitize_icon(source, manifest.icon.as_deref())?;
    Ok(manifest)
}

fn render_policy_rule(
    rule: &PolicyRuleConfig,
    params: &BTreeMap<String, String>,
) -> PolicyRuleConfig {
    PolicyRuleConfig {
        effect: rule.effect,
        methods: rule.methods.clone(),
        hosts: rule
            .hosts
            .iter()
            .map(|h| render_params(h, params))
            .collect(),
        paths: rule
            .paths
            .iter()
            .map(|p| render_params(p, params))
            .collect(),
    }
}

fn filter_injector_hosts(
    raw_hosts: &[String],
    params: &BTreeMap<String, String>,
    allowed_inject_hosts: &[String],
) -> Vec<String> {
    raw_hosts
        .iter()
        .map(|h| render_params(h, params).trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| pattern_is_subset_of(h, allowed_inject_hosts))
        .collect()
}

fn check_schemes(
    id: &str,
    schemes: &[String],
    allow_insecure_http: bool,
) -> Result<Vec<String>, PluginError> {
    let mut out = Vec::with_capacity(schemes.len());
    for s in schemes {
        let sl = s.to_ascii_lowercase();
        if sl != "https" && !allow_insecure_http {
            return Err(PluginError::InsecureScheme(id.into()));
        }
        out.push(sl);
    }
    Ok(out)
}

fn build_injector(
    idx: usize,
    cfg: &InjectRuleConfig,
    params: &BTreeMap<String, String>,
    allowed_inject_hosts: &[String],
    allow_insecure_http: bool,
) -> Result<Arc<dyn AuthInjector>, PluginError> {
    let id = if cfg.id.is_empty() {
        format!("inject-{idx}")
    } else {
        cfg.id.clone()
    };
    let hosts = filter_injector_hosts(&cfg.hosts, params, allowed_inject_hosts);
    let schemes = check_schemes(&id, &cfg.schemes, allow_insecure_http)?;

    match cfg.mode {
        InjectMode::Bearer => Ok(Arc::new(BearerHeaderInjector {
            id,
            hosts,
            schemes,
            header: render_params(&cfg.header, params),
            match_schemes: cfg.accept_schemes.clone(),
            inject_scheme: cfg
                .inject_scheme
                .as_deref()
                .map(|s| render_params(s, params))
                .unwrap_or_else(|| "Bearer".to_string()),
            secret_field: cfg.secret.clone(),
        })),
        InjectMode::Basic => Ok(Arc::new(BasicAuthInjector {
            id,
            hosts,
            schemes,
            expected_username: cfg.expected_username.clone(),
            inject_username: render_params(&cfg.username, params),
            password_field: cfg.secret.clone(),
        })),
        InjectMode::Header => Ok(Arc::new(HeaderTokenInjector {
            id,
            hosts,
            schemes,
            header: render_params(&cfg.header, params),
            inject_scheme: cfg
                .inject_scheme
                .as_deref()
                .map(|s| render_params(s, params))
                .unwrap_or_default(),
            secret_field: cfg.secret.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::injector::{InjectionContext, InjectionOutcome, UpstreamHttpRequest};
    use cx_crypto::hash_secret_hex;
    use secrecy::SecretString;

    #[tokio::test]
    async fn multi_platform_profile_isolates_virtual_keys_and_policies() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();
        let profile = reg
            .resolve_profile(&ProfileSpec {
                name: "dev-agent".into(),
                description: "GitHub RO + OpenAI + two internal HTTP APIs".into(),
                allowed_groups: vec!["eng".into()],
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
                            SecretBinding::Env {
                                var: "REAL_GITHUB_TOKEN".into(),
                            },
                        )]),
                        virtual_key_override: None,
                        preset: Some("readonly".into()),
                        rules: vec![],
                        routing: PlatformRoutingOverride {
                            inject_hosts: Some(vec!["api.github.com".into()]),
                            ..Default::default()
                        },
                        allow_insecure_http: false,
                    },
                    PlatformSpec {
                        id: "openai".into(),
                        provider_id: "openai".into(),
                        params: BTreeMap::new(),
                        secrets: BTreeMap::from([(
                            "api_key".into(),
                            SecretBinding::Env {
                                var: "REAL_OPENAI_KEY".into(),
                            },
                        )]),
                        virtual_key_override: None,
                        preset: Some("full".into()),
                        rules: vec![],
                        routing: PlatformRoutingOverride::default(),
                        allow_insecure_http: false,
                    },
                    PlatformSpec {
                        id: "jira".into(),
                        provider_id: "generic-http".into(),
                        params: BTreeMap::from([
                            ("host".into(), "jira.example.com".into()),
                            ("env_var".into(), "JIRA_TOKEN".into()),
                        ]),
                        secrets: BTreeMap::new(),
                        virtual_key_override: None,
                        preset: Some("full".into()),
                        rules: vec![],
                        routing: PlatformRoutingOverride::default(),
                        allow_insecure_http: false,
                    },
                    PlatformSpec {
                        id: "billing".into(),
                        provider_id: "generic-http".into(),
                        params: BTreeMap::from([
                            ("host".into(), "billing.example.com".into()),
                            ("env_var".into(), "BILLING_TOKEN".into()),
                        ]),
                        secrets: BTreeMap::new(),
                        virtual_key_override: None,
                        preset: Some("full".into()),
                        rules: vec![],
                        routing: PlatformRoutingOverride::default(),
                        allow_insecure_http: false,
                    },
                ],
            })
            .unwrap();

        assert_eq!(profile.platforms.len(), 4);
        assert_eq!(
            profile.routing.inject_hosts,
            vec![
                "api.github.com",
                "api.openai.com",
                "jira.example.com",
                "billing.example.com"
            ]
        );

        let vks = profile.generate_ephemeral_virtual_keys();
        assert!(vks["github"].starts_with("gho_cx_"));
        assert!(vks["openai"].starts_with("sk-cx-"));
        assert!(vks["jira"].starts_with("cx_vk_"));
        assert!(vks["billing"].starts_with("cx_vk_"));

        let launch = profile.build_client_launch_spec(&vks);
        assert_eq!(launch.env_inject["GH_TOKEN"], vks["github"]);
        assert_eq!(launch.env_inject["OPENAI_API_KEY"], vks["openai"]);
        assert_eq!(launch.env_inject["JIRA_TOKEN"], vks["jira"]);
        assert_eq!(launch.env_inject["BILLING_TOKEN"], vks["billing"]);

        // GitHub platform only accepts GitHub virtual key and enforces readonly policy
        let gh = profile.find_platform_for_l7_host("api.github.com").unwrap();
        assert_eq!(gh.id, "github");
        let gh_hashes = vec![hash_secret_hex(&vks["github"])];
        let ctx = InjectionContext {
            allowed_vk_hashes: &gh_hashes,
        };
        let secrets = BTreeMap::from([(
            "token".into(),
            SecretString::from("ghp_REAL_TOKEN".to_string()),
        )]);
        let mut req = UpstreamHttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.github.com".into(),
            port: 443,
            path_and_query: "/user".into(),
            headers: vec![("Authorization".into(), format!("token {}", vks["github"]).into_bytes())],
        };
        let outcome = gh.injectors[0].inject(&mut req, &ctx, &secrets).await.unwrap();
        assert_eq!(outcome, InjectionOutcome::Injected);
        assert_eq!(req.headers[0].1, b"Bearer ghp_REAL_TOKEN");

        // OpenAI virtual key is rejected by GitHub injector!
        let mut wrong_vk_req = UpstreamHttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.github.com".into(),
            port: 443,
            path_and_query: "/user".into(),
            headers: vec![("Authorization".into(), format!("Bearer {}", vks["openai"]).into_bytes())],
        };
        assert!(gh.injectors[0].inject(&mut wrong_vk_req, &ctx, &secrets).await.is_err());
    }

    #[test]
    fn rejects_duplicate_named_provider_and_env_or_host_conflicts() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();

        // Duplicate named provider (github twice) rejected
        let dup_named = reg.resolve_profile(&ProfileSpec {
            name: "dup".into(),
            description: String::new(),
            allowed_groups: vec!["eng".into()],
            allowed_users: vec![],
            deny_hosts: vec![],
            fallback: DefaultRouteAction::ClientPassthrough,
            platforms: vec![
                PlatformSpec {
                    id: "github".into(),
                    provider_id: "github".into(),
                    params: BTreeMap::new(),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
                PlatformSpec {
                    id: "github-2".into(),
                    provider_id: "github".into(),
                    params: BTreeMap::new(),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
            ],
        });
        assert!(matches!(
            dup_named,
            Err(PluginError::NamedProviderIdMismatch(..))
        ));

        // Two generic-http entries sharing default env_var API_TOKEN rejected
        let env_conflict = reg.resolve_profile(&ProfileSpec {
            name: "env-clash".into(),
            description: String::new(),
            allowed_groups: vec!["eng".into()],
            allowed_users: vec![],
            deny_hosts: vec![],
            fallback: DefaultRouteAction::ClientPassthrough,
            platforms: vec![
                PlatformSpec {
                    id: "svc-a".into(),
                    provider_id: "generic-http".into(),
                    params: BTreeMap::from([("host".into(), "a.example.com".into())]),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
                PlatformSpec {
                    id: "svc-b".into(),
                    provider_id: "generic-http".into(),
                    params: BTreeMap::from([("host".into(), "b.example.com".into())]),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
            ],
        });
        assert!(matches!(env_conflict, Err(PluginError::EnvConflict { .. })));

        // Two generic-http entries claiming the same host rejected
        let host_conflict = reg.resolve_profile(&ProfileSpec {
            name: "host-clash".into(),
            description: String::new(),
            allowed_groups: vec!["eng".into()],
            allowed_users: vec![],
            deny_hosts: vec![],
            fallback: DefaultRouteAction::ClientPassthrough,
            platforms: vec![
                PlatformSpec {
                    id: "svc-a".into(),
                    provider_id: "generic-http".into(),
                    params: BTreeMap::from([
                        ("host".into(), "api.example.com".into()),
                        ("env_var".into(), "A_TOKEN".into()),
                    ]),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
                PlatformSpec {
                    id: "svc-b".into(),
                    provider_id: "generic-http".into(),
                    params: BTreeMap::from([
                        ("host".into(), "api.example.com".into()),
                        ("env_var".into(), "B_TOKEN".into()),
                    ]),
                    secrets: BTreeMap::new(),
                    virtual_key_override: None,
                    preset: None,
                    rules: vec![],
                    routing: PlatformRoutingOverride::default(),
                    allow_insecure_http: false,
                },
            ],
        });
        assert!(matches!(host_conflict, Err(PluginError::HostConflict { .. })));
    }

    #[test]
    fn profile_cannot_expand_outside_provider_hosts() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();
        let res = reg.resolve_profile(&ProfileSpec {
            name: "bad".into(),
            description: String::new(),
            allowed_groups: vec!["eng".into()],
            allowed_users: vec![],
            deny_hosts: vec![],
            fallback: DefaultRouteAction::ClientPassthrough,
            platforms: vec![PlatformSpec {
                id: "github".into(),
                provider_id: "github".into(),
                params: BTreeMap::new(),
                secrets: BTreeMap::new(),
                virtual_key_override: None,
                preset: None,
                rules: vec![],
                routing: PlatformRoutingOverride {
                    inject_hosts: Some(vec!["evil.example.com".into()]),
                    ..Default::default()
                },
                allow_insecure_http: false,
            }],
        });
        assert!(res.is_err());
    }

    #[test]
    fn provider_catalog_exposes_display_name_and_validates_icons() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();
        let catalog = reg.list_provider_catalog();

        let gh = catalog.iter().find(|p| p.id == "github").unwrap();
        assert_eq!(gh.name, "GitHub");
        assert_eq!(gh.icon.as_deref(), Some("github"));

        let oa = catalog.iter().find(|p| p.id == "openai").unwrap();
        assert_eq!(oa.name, "OpenAI");
        assert_eq!(oa.icon.as_deref(), Some("openai"));

        let generic = catalog.iter().find(|p| p.id == "generic-http").unwrap();
        assert_eq!(generic.name, "自定义 HTTP");
        assert_eq!(generic.icon.as_deref(), Some("globe"));
        assert!(generic.allow_multiple);

        // Unsafe icon schemes must be rejected
        let bad_js = r#"
id = "evil"
name = "Evil"
icon = "javascript:alert(1)"
"#;
        assert!(parse_manifest("test", bad_js).is_err());

        let bad_remote = r#"
id = "remote"
icon = "https://example.com/logo.png"
"#;
        assert!(parse_manifest("test", bad_remote).is_err());

        // Safe base64 PNG data URI and fallback name -> id must succeed
        let ok_data = r#"
id = "corp-api"
icon = "data:image/png;base64,iVBORw0KGgo="
"#;
        let parsed = parse_manifest("test", ok_data).unwrap();
        assert_eq!(parsed.display_name(), "corp-api");
        assert!(parsed.icon.as_deref().unwrap().starts_with("data:image/png;base64,"));
    }
}
