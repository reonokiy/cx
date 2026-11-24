use std::net::IpAddr;

use psl::Psl;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("empty host pattern")]
    EmptyHost,
    #[error("invalid host pattern '{0}': {1}")]
    InvalidPattern(String, String),
    #[error("forbidden broad wildcard host pattern '{0}': matches public suffix")]
    PublicSuffixWildcard(String),
    #[error("IP literal or localhost '{0}' is not allowed for credential injection")]
    PrivateOrIpNotAllowed(String),
    #[error("profile inject host '{0}' exceeds plugin allowed hosts")]
    HostOutOfPluginScope(String),
}

#[derive(Debug, Clone)]
pub struct HostPatternValidator {
    pub allow_private_targets: bool,
    pub allow_apex_wildcard: bool,
}

impl Default for HostPatternValidator {
    fn default() -> Self {
        Self {
            allow_private_targets: false,
            allow_apex_wildcard: false,
        }
    }
}

impl HostPatternValidator {
    /// Strict validation for Tier 1 (`inject_hosts`) where real credentials may be injected.
    pub fn validate_inject_host(&self, raw: &str) -> Result<String, ValidationError> {
        let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(ValidationError::EmptyHost);
        }
        if host.contains('/') || host.contains(':') || host.contains(' ') {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "must be a hostname without scheme, port, or path".into(),
            ));
        }

        if host == "*" || host == "*.*" {
            return Err(ValidationError::PublicSuffixWildcard(raw.into()));
        }

        if let Some(rest) = host.strip_prefix("*.") {
            if rest.contains('*') {
                return Err(ValidationError::InvalidPattern(
                    raw.into(),
                    "only a single leftmost wildcard label is allowed".into(),
                ));
            }
            validate_dns_labels(rest, raw)?;
            self.check_not_public_suffix(rest, raw, true)?;
            if !self.allow_apex_wildcard {
                // Require at least one subdomain label above the registrable domain (e.g. `*.s3.amazonaws.com`)
                if let Some(reg_domain) = psl::List.domain(rest.as_bytes()) {
                    if reg_domain.as_bytes() == rest.as_bytes() {
                        return Err(ValidationError::InvalidPattern(
                            raw.into(),
                            "apex wildcard is disallowed for inject_hosts by default; use exact host or deeper subdomain wildcard".into(),
                        ));
                    }
                }
            }
            return Ok(format!("*.{rest}"));
        }

        if host.contains('*') {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "wildcard '*' is only allowed as leftmost label '*.example.com'".into(),
            ));
        }

        if host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok() {
            if !self.allow_private_targets {
                return Err(ValidationError::PrivateOrIpNotAllowed(raw.into()));
            }
            return Ok(host);
        }

        validate_dns_labels(&host, raw)?;
        Ok(host)
    }

    /// Validation for Tier 2 (`server_tunnel_hosts`): still blocks `*` and bare public suffixes (`*.com`),
    /// while permitting apex wildcards like `*.githubusercontent.com`.
    pub fn validate_tunnel_host(&self, raw: &str) -> Result<String, ValidationError> {
        let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Err(ValidationError::EmptyHost);
        }
        if host == "*" || host == "*.*" {
            return Err(ValidationError::PublicSuffixWildcard(raw.into()));
        }
        if let Some(rest) = host.strip_prefix("*.") {
            if rest.contains('*') {
                return Err(ValidationError::InvalidPattern(
                    raw.into(),
                    "only a single leftmost wildcard label is allowed".into(),
                ));
            }
            validate_dns_labels(rest, raw)?;
            // Tier 2 carries zero secrets: block ICANN public suffixes (*.com, *.co.uk),
            // while permitting private vendor CDN suffixes like *.githubusercontent.com.
            self.check_not_public_suffix(rest, raw, false)?;
            return Ok(format!("*.{rest}"));
        }
        if host.contains('*') {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "wildcard '*' is only allowed as leftmost label".into(),
            ));
        }
        if host == "localhost" || host.parse::<IpAddr>().is_ok() {
            if !self.allow_private_targets {
                return Err(ValidationError::PrivateOrIpNotAllowed(raw.into()));
            }
            return Ok(host);
        }
        validate_dns_labels(&host, raw)?;
        Ok(host)
    }

    fn check_not_public_suffix(
        &self,
        suffix_candidate: &str,
        raw: &str,
        block_private_psl: bool,
    ) -> Result<(), ValidationError> {
        if !suffix_candidate.contains('.') {
            return Err(ValidationError::PublicSuffixWildcard(raw.into()));
        }
        if let Some(suffix) = psl::List.suffix(suffix_candidate.as_bytes()) {
            if suffix.as_bytes() == suffix_candidate.as_bytes() {
                if block_private_psl || suffix.typ() == Some(psl::Type::Icann) {
                    return Err(ValidationError::PublicSuffixWildcard(raw.into()));
                }
            }
        }
        Ok(())
    }
}

fn validate_dns_labels(domain: &str, raw: &str) -> Result<(), ValidationError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(ValidationError::InvalidPattern(
            raw.into(),
            "invalid hostname length".into(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "empty or overlong DNS label".into(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "DNS label cannot start or end with '-'".into(),
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ValidationError::InvalidPattern(
                raw.into(),
                "DNS label contains invalid characters".into(),
            ));
        }
    }
    Ok(())
}

/// Check if `narrow` host pattern is wholly covered by at least one `allowed` plugin pattern.
pub fn pattern_is_subset_of(narrow: &str, allowed: &[String]) -> bool {
    let n = narrow.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|a| {
        let a_lc = a.trim_end_matches('.').to_ascii_lowercase();
        if n == a_lc {
            return true;
        }
        if let Some(a_suffix) = a_lc.strip_prefix("*.") {
            if let Some(n_suffix) = n.strip_prefix("*.") {
                return n_suffix == a_suffix
                    || n_suffix.ends_with(&format!(".{a_suffix}"));
            }
            return cx_protocol::host_matches_pattern(&n, &a_lc);
        }
        false
    })
}

/// Check if two host patterns (`a` and `b`) can match any common hostname.
pub fn patterns_overlap(a: &str, b: &str) -> bool {
    pattern_is_subset_of(a, &[b.to_string()]) || pattern_is_subset_of(b, &[a.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_dangerous_wildcards_and_allows_valid_hosts() {
        let v = HostPatternValidator::default();
        assert!(v.validate_inject_host("api.github.com").is_ok());
        assert!(v.validate_inject_host("*.api.example.com").is_ok());

        // Forbidden broad wildcards (both ICANN and multi-tenant Private PSL suffixes!)
        assert!(v.validate_inject_host("*").is_err());
        assert!(v.validate_inject_host("*.com").is_err());
        assert!(v.validate_inject_host("*.co.uk").is_err());
        assert!(v.validate_inject_host("*.github.io").is_err());
        assert!(v.validate_inject_host("*.s3.amazonaws.com").is_err());
        assert!(v.validate_inject_host("*.github.com").is_err()); // apex wildcard disallowed by default for inject
        assert!(v.validate_inject_host("127.0.0.1").is_err());
        assert!(v.validate_inject_host("localhost").is_err());

        // Tunnel hosts allow apex wildcard on private registrable domain, still block public suffixes
        assert!(v.validate_tunnel_host("*.githubusercontent.com").is_ok());
        assert!(v.validate_tunnel_host("*.com").is_err());
        assert!(v.validate_tunnel_host("*").is_err());
    }
}
