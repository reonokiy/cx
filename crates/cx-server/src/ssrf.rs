use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use thiserror::Error;
use tokio::net::{TcpStream, lookup_host};

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("DNS resolution failed for {0}:{1}: {2}")]
    Dns(String, u16, std::io::Error),
    #[error("no IP addresses resolved for {0}:{1}")]
    NoAddresses(String, u16),
    #[error("SSRF protection blocked dial to private/reserved IP {0}")]
    BlockedIp(IpAddr),
    #[error("upstream TCP connect failed: {0}")]
    Connect(std::io::Error),
}

#[derive(Debug, Clone)]
pub struct SsrfPolicy {
    pub block_private_ips: bool,
    pub allow_cidrs: Vec<IpNet>,
    /// Optional test/dev dial overrides: hostname -> "ip:port".
    pub upstream_overrides: BTreeMap<String, String>,
}

impl SsrfPolicy {
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        if !self.block_private_ips {
            return true;
        }
        if self.allow_cidrs.iter().any(|net| net.contains(&ip)) {
            return true;
        }
        !is_private_or_reserved(ip)
    }
}

pub fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_v4_private_or_reserved(v4),
        IpAddr::V6(v6) => is_v6_private_or_reserved(v6),
    }
}

fn is_v4_private_or_reserved(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()                      // 127.0.0.0/8
        || ip.is_private()                // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()             // 169.254.0.0/16 (AWS/GCP/Azure metadata!)
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.is_unspecified()            // 0.0.0.0
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 Fake-IP/benchmark
        || o[0] >= 240
}

fn is_v6_private_or_reserved(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_v4_private_or_reserved(v4);
    }
    let seg0 = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 ULA
        || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// Resolve DNS and validate EVERY resolved IP before dialing to prevent SSRF & DNS rebinding.
pub async fn ssrf_safe_connect(
    host: &str,
    port: u16,
    policy: &SsrfPolicy,
) -> Result<TcpStream, SsrfError> {
    let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(override_addr) = policy.upstream_overrides.get(&host_lc) {
        let sock: SocketAddr = override_addr
            .parse()
            .map_err(|_| SsrfError::NoAddresses(host.into(), port))?;
        return TcpStream::connect(sock).await.map_err(SsrfError::Connect);
    }

    let addrs: Vec<SocketAddr> = lookup_host((host_lc.as_str(), port))
        .await
        .map_err(|e| SsrfError::Dns(host_lc.clone(), port, e))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::NoAddresses(host_lc, port));
    }

    // Strict check: refuse if any returned IP is private/reserved.
    for addr in &addrs {
        if !policy.is_ip_allowed(addr.ip()) {
            return Err(SsrfError::BlockedIp(addr.ip()));
        }
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(SsrfError::Connect(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connect failed")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_metadata_loopback_and_rfc1918() {
        let p = SsrfPolicy {
            block_private_ips: true,
            allow_cidrs: vec![],
            upstream_overrides: BTreeMap::new(),
        };
        assert!(!p.is_ip_allowed("127.0.0.1".parse().unwrap()));
        assert!(!p.is_ip_allowed("169.254.169.254".parse().unwrap()));
        assert!(!p.is_ip_allowed("10.0.0.1".parse().unwrap()));
        assert!(!p.is_ip_allowed("192.168.1.5".parse().unwrap()));
        assert!(!p.is_ip_allowed("::1".parse().unwrap()));
        assert!(!p.is_ip_allowed("fc00::1".parse().unwrap()));
        assert!(p.is_ip_allowed("140.82.121.6".parse().unwrap())); // GitHub public IP
    }
}
