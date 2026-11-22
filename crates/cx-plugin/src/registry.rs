use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use cx_crypto::{VirtualKeySpec, VirtualKeySpecError};
use cx_protocol::{ClientLaunchSpec, DefaultRouteAction, GitRewriteRule, RoutingPolicy};
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
use crate::validator::{HostPatternValidator, ValidationError, pattern_is_subset_of};

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error in {0}: {1}")]
    Toml(String, String),
    #[error("provider '{0}' not found")]
    NotFound(String),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScope {
    #[default]
    Shared,
    Personal,
}

/// Strongly-typed secret source binding configured under `[secrets.<field>]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SecretBinding {
    /// Read directly from a server environment variable.
    Env { var: String },
    /// Read from the server's envelope-encrypted database.
    Db {
        #[serde(default)]
        scope: SecretScope,
        name: String,
        /// Optional field key inside the stored secret object (defaults to the `[secrets.<field>]` name).
        #[serde(default)]
        field: Option<String>,
    },
    /// Literal value (intended for local dev / automated tests only).
    Inline { value: String },
}

#[derive(Debug, Clone)]
pub struct ProfileSpec {
    pub name: String,
    pub provider_id: String,
    pub params: BTreeMap<String, String>,
    /// Secret field name -> structured binding (`[secrets.<field>]`).
    pub secrets: BTreeMap<String, SecretBinding>,
    /// Optional profile-level override for virtual key generation rules.
    pub virtual_key_override: Option<VirtualKeySpec>,
    pub preset: Option<String>,
    pub rules: Vec<PolicyRuleConfig>,
    pub override_inject_hosts: Option<Vec<String>>,
    pub override_passthrough_hosts: Option<Vec<String>>,
    pub override_passthrough_ports: Option<Vec<u16>>,
    pub deny_hosts: Vec<String>,
    pub fallback: Option<DefaultRouteAction>,
    pub allowed_groups: Vec<String>,
    pub allowed_users: Vec<String>,
    pub allow_insecure_http: bool,
}

pub struct ResolvedProfile {
    pub name: String,
    pub provider_id: String,
    pub resolved_params: BTreeMap<String, String>,
    pub secret_bindings: BTreeMap<String, SecretBinding>,
    pub virtual_key: VirtualKeySpec,
    pub routing: RoutingPolicy,
    pub env_template: BTreeMap<String, String>,
    pub git_template: Vec<(String, Vec<String>, String)>,
    pub injectors: Vec<Arc<dyn AuthInjector>>,
    pub policy: CompiledPolicy,
    pub allowed_groups: Vec<String>,
    pub allowed_users: Vec<String>,
}

impl ResolvedProfile {
    pub fn generate_virtual_key(&self) -> String {
        self.virtual_key.generate()
    }

    pub fn build_client_launch_spec(&self, virtual_key: &str) -> ClientLaunchSpec {
        let mut env_inject = BTreeMap::new();
        for (raw_k, raw_v) in &self.env_template {
            let k = render_params(raw_k, &self.resolved_params);
            let v = render_client_template(raw_v, &self.resolved_params, virtual_key);
            env_inject.insert(k, v);
        }

        let git_rewrites = self
            .git_template
            .iter()
            .map(|(host, from, user)| GitRewriteRule {
                host: host.clone(),
                from: from.clone(),
                credential_username: user.clone(),
                virtual_key: virtual_key.to_string(),
            })
            .collect();

        ClientLaunchSpec {
            env_inject,
            git_rewrites,
        }
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
        let catalog = self.catalog.load();
        let manifest = catalog
            .manifests
            .get(&spec.provider_id)
            .ok_or_else(|| PluginError::NotFound(spec.provider_id.clone()))?;

        // 1. Validate virtual key generation spec (profile override > provider default)
        let virtual_key = spec
            .virtual_key_override
            .clone()
            .unwrap_or_else(|| manifest.virtual_key.clone());
        virtual_key.validate()?;

        // 2. Resolve parameters (profile override > provider default)
        let mut resolved_params = BTreeMap::new();
        for (k, def) in &manifest.params {
            if let Some(v) = spec.params.get(k) {
                resolved_params.insert(k.clone(), v.clone());
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
            resolved_params.entry(k.clone()).or_insert_with(|| v.clone());
        }

        // 3. Automatically aggregate & validate Tier 1 inject hosts from `[[inject]]` rules (single source of truth!)
        let mut seen_inject = BTreeSet::new();
        let mut provider_inject_hosts = Vec::new();
        for inj in &manifest.inject {
            for h in &inj.hosts {
                let validated = self
                    .validator
                    .validate_inject_host(&render_params(h, &resolved_params))?;
                if seen_inject.insert(validated.clone()) {
                    provider_inject_hosts.push(validated);
                }
            }
        }

        // 4. Validate Tier 2 passthrough hosts
        let provider_tunnel_hosts: Vec<String> = manifest
            .passthrough
            .hosts
            .iter()
            .map(|h| {
                self.validator
                    .validate_tunnel_host(&render_params(h, &resolved_params))
            })
            .collect::<Result<_, _>>()?;

        // 5. Apply Profile narrowing (Profile cannot expand inject hosts beyond provider!)
        let inject_hosts = match &spec.override_inject_hosts {
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

        let server_tunnel_hosts = match &spec.override_passthrough_hosts {
            Some(custom) => custom
                .iter()
                .map(|h| self.validator.validate_tunnel_host(h))
                .collect::<Result<Vec<_>, _>>()?,
            None => provider_tunnel_hosts,
        };

        let server_tunnel_ports = spec
            .override_passthrough_ports
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

        let routing = RoutingPolicy {
            deny_hosts: spec.deny_hosts.clone(),
            inject_hosts: inject_hosts.clone(),
            server_tunnel_hosts,
            server_tunnel_ports,
            server_http_passthrough_hosts,
            default_action: spec.fallback.unwrap_or(manifest.fallback),
        };

        // 6. Store strongly-typed `[secrets.*]` bindings
        let secret_bindings = spec.secrets.clone();

        // 7. Build slot-scoped injectors constrained strictly to resolved `inject_hosts`
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

        // 8. Compile structured policy rules (preset + profile extra rules)
        let mut compiled_rule_cfgs = Vec::new();
        if let Some(preset_name) = &spec.preset {
            let preset_rules = manifest
                .presets
                .get(preset_name)
                .ok_or_else(|| {
                    PluginError::UnknownPreset(spec.provider_id.clone(), preset_name.clone())
                })?;
            for r in preset_rules {
                compiled_rule_cfgs.push(render_policy_rule(r, &resolved_params));
            }
        }
        for r in &spec.rules {
            compiled_rule_cfgs.push(render_policy_rule(r, &resolved_params));
        }
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

        Ok(ResolvedProfile {
            name: spec.name.clone(),
            provider_id: manifest.id.clone(),
            resolved_params,
            secret_bindings,
            virtual_key,
            routing,
            env_template: manifest.env.clone(),
            git_template,
            injectors,
            policy,
            allowed_groups: spec.allowed_groups.clone(),
            allowed_users: spec.allowed_users.clone(),
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

fn parse_manifest(source: &str, raw: &str) -> Result<ProviderManifest, PluginError> {
    let manifest: ProviderManifest =
        toml::from_str(raw).map_err(|e| PluginError::Toml(source.into(), e.to_string()))?;
    manifest.virtual_key.validate()?;
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
    async fn github_provider_resolves_and_injects_only_allowed_host() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();
        let profile = reg
            .resolve_profile(&ProfileSpec {
                name: "github-ro".into(),
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
                override_inject_hosts: Some(vec!["api.github.com".into()]),
                override_passthrough_hosts: None,
                override_passthrough_ports: None,
                deny_hosts: vec![],
                fallback: None,
                allowed_groups: vec!["eng".into()],
                allowed_users: vec![],
                allow_insecure_http: false,
            })
            .unwrap();

        // Narrowing worked: github.com injector was excluded
        assert_eq!(profile.routing.inject_hosts, vec!["api.github.com"]);
        assert_eq!(profile.injectors.len(), 1);

        let vk = profile.generate_virtual_key();
        assert!(vk.starts_with("gho_cx_"));
        assert_eq!(vk.len(), "gho_cx_".len() + 32);

        let vk_hashes = vec![hash_secret_hex(&vk)];
        let ctx = InjectionContext {
            allowed_vk_hashes: &vk_hashes,
        };
        let mut secrets = BTreeMap::new();
        secrets.insert("token".into(), SecretString::from("ghp_REAL_TOKEN".to_string()));

        let mut req = UpstreamHttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.github.com".into(),
            port: 443,
            path_and_query: "/user".into(),
            headers: vec![("Authorization".into(), format!("token {vk}").into_bytes())],
        };

        let inj = &profile.injectors[0];
        assert!(inj.matches_target("api.github.com", "https"));
        assert!(!inj.matches_target("evil.com", "https"));

        let outcome = inj.inject(&mut req, &ctx, &secrets).await.unwrap();
        assert_eq!(outcome, InjectionOutcome::Injected);
        assert_eq!(req.headers[0].1, b"Bearer ghp_REAL_TOKEN");
    }

    #[test]
    fn profile_cannot_expand_outside_provider_hosts() {
        let reg = ProviderRegistry::new(None, true, HostPatternValidator::default()).unwrap();
        let res = reg.resolve_profile(&ProfileSpec {
            name: "bad".into(),
            provider_id: "github".into(),
            params: BTreeMap::new(),
            secrets: BTreeMap::new(),
            virtual_key_override: None,
            preset: None,
            rules: vec![],
            override_inject_hosts: Some(vec!["evil.example.com".into()]),
            override_passthrough_hosts: None,
            override_passthrough_ports: None,
            deny_hosts: vec![],
            fallback: None,
            allowed_groups: vec!["eng".into()],
            allowed_users: vec![],
            allow_insecure_http: false,
        });
        assert!(res.is_err());
    }
}
