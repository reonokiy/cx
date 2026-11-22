use cx_protocol::host_matches_pattern;
use globset::{Glob, GlobMatcher};
use thiserror::Error;

use crate::manifest::{PolicyEffect, PolicyRuleConfig};

#[derive(Debug, Error)]
pub enum PolicyCompileError {
    #[error("invalid path glob '{0}': {1}")]
    InvalidGlob(String, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

struct CompiledRule {
    effect: PolicyEffect,
    methods: Vec<String>,
    hosts: Vec<String>,
    paths: Vec<GlobMatcher>,
}

/// Deny-by-default L7 HTTP policy engine (explicit deny always wins over allow).
pub struct CompiledPolicy {
    rules: Vec<CompiledRule>,
}

impl CompiledPolicy {
    pub fn compile(configs: &[PolicyRuleConfig]) -> Result<Self, PolicyCompileError> {
        let mut rules = Vec::with_capacity(configs.len());
        for cfg in configs {
            let mut paths = Vec::with_capacity(cfg.paths.len());
            for p in &cfg.paths {
                let glob = Glob::new(p)
                    .map_err(|e| PolicyCompileError::InvalidGlob(p.clone(), e.to_string()))?;
                paths.push(glob.compile_matcher());
            }
            rules.push(CompiledRule {
                effect: cfg.effect,
                methods: cfg.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                hosts: cfg
                    .hosts
                    .iter()
                    .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
                paths,
            });
        }
        Ok(Self { rules })
    }

    pub fn evaluate(&self, method: &str, host: &str, path_and_query: &str) -> PolicyDecision {
        let method_up = method.to_ascii_uppercase();
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        let path_only = path_and_query
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(path_and_query);

        let mut allowed = false;
        for rule in &self.rules {
            let method_ok = rule.methods.is_empty()
                || rule.methods.iter().any(|m| m == "*" || m == &method_up);
            if !method_ok {
                continue;
            }
            let host_ok = rule.hosts.is_empty()
                || rule
                    .hosts
                    .iter()
                    .any(|p| p == "*" || host_matches_pattern(&host_lc, p));
            if !host_ok {
                continue;
            }
            let path_ok = rule.paths.is_empty()
                || rule.paths.iter().any(|m| m.is_match(path_only));
            if !path_ok {
                continue;
            }

            match rule.effect {
                PolicyEffect::Deny => {
                    return PolicyDecision::Deny(format!(
                        "explicitly denied by policy ({method_up} {host_lc}{path_only})"
                    ));
                }
                PolicyEffect::Allow => {
                    allowed = true;
                }
            }
        }

        if allowed {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny(format!(
                "no allow policy matched ({method_up} {host_lc}{path_only})"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_structured_rules_and_deny_precedence() {
        let rules = vec![
            PolicyRuleConfig {
                effect: PolicyEffect::Allow,
                methods: vec!["GET".into(), "HEAD".into()],
                hosts: vec!["api.github.com".into()],
                paths: vec!["/user".into(), "/repos/my-org/**".into()],
            },
            PolicyRuleConfig {
                effect: PolicyEffect::Deny,
                methods: vec!["*".into()],
                hosts: vec!["api.github.com".into()],
                paths: vec!["/repos/my-org/secret-repo/**".into()],
            },
        ];
        let policy = CompiledPolicy::compile(&rules).unwrap();

        assert_eq!(
            policy.evaluate("GET", "api.github.com", "/repos/my-org/cx/pulls?state=open"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate("GET", "api.github.com", "/user"),
            PolicyDecision::Allow
        );
        assert!(matches!(
            policy.evaluate("POST", "api.github.com", "/repos/my-org/cx/pulls"),
            PolicyDecision::Deny(_)
        ));
        assert!(matches!(
            policy.evaluate("GET", "api.github.com", "/repos/my-org/secret-repo/issues"),
            PolicyDecision::Deny(_)
        ));
    }
}
