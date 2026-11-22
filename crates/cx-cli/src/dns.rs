use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use cx_protocol::{RouteDecision, RoutingPolicy};

/// RFC 2544 benchmark range `198.18.0.0/15` reserved for Fake-IP domain mapping.
const FAKE_IP_START: u32 = u32::from_be_bytes([198, 18, 0, 10]);
const FAKE_IP_END: u32 = u32::from_be_bytes([198, 19, 255, 250]);

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const RCODE_NOERROR: u16 = 0;
const RCODE_FORMERR: u16 = 1;
const RCODE_REFUSED: u16 = 5;

pub struct FakeIpDns {
    policy: RoutingPolicy,
    state: Mutex<FakeIpState>,
}

struct FakeIpState {
    next_ip: u32,
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<Ipv4Addr, String>,
}

impl FakeIpDns {
    pub fn new(policy: RoutingPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(FakeIpState {
                next_ip: FAKE_IP_START,
                domain_to_ip: HashMap::new(),
                ip_to_domain: HashMap::new(),
            }),
        }
    }

    pub fn is_fake_ip(ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        (FAKE_IP_START..=FAKE_IP_END).contains(&v)
    }

    pub fn lookup_domain(&self, ip: Ipv4Addr) -> Option<String> {
        self.state.lock().unwrap().ip_to_domain.get(&ip).cloned()
    }

    pub fn allocate_ip(&self, domain: &str) -> Ipv4Addr {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut st = self.state.lock().unwrap();
        if let Some(&existing) = st.domain_to_ip.get(&key) {
            return existing;
        }
        let ip = Ipv4Addr::from(st.next_ip);
        st.next_ip = if st.next_ip >= FAKE_IP_END {
            FAKE_IP_START
        } else {
            st.next_ip + 1
        };
        if let Some(old_domain) = st.ip_to_domain.insert(ip, key.clone()) {
            st.domain_to_ip.remove(&old_domain);
        }
        st.domain_to_ip.insert(key, ip);
        ip
    }

    /// Parse a raw DNS UDP query payload and synthesize an RFC 1035 DNS reply.
    pub fn handle_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let tx_id = [query[0], query[1]];
        let rd_bit = query[2] & 0x01;
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount == 0 {
            return Some(build_empty_reply(tx_id, rd_bit, RCODE_FORMERR, &[]));
        }

        let Some((qname, next_offset)) = parse_qname(query, 12) else {
            return Some(build_empty_reply(tx_id, rd_bit, RCODE_FORMERR, &[]));
        };
        if next_offset + 4 > query.len() {
            return Some(build_empty_reply(tx_id, rd_bit, RCODE_FORMERR, &[]));
        }

        let qtype = u16::from_be_bytes([query[next_offset], query[next_offset + 1]]);
        let qclass = u16::from_be_bytes([query[next_offset + 2], query[next_offset + 3]]);
        let question_slice = &query[12..next_offset + 4];

        // Evaluate deny rules first (use port 443 as canonical check for DNS-level deny).
        if self.policy.resolve(&qname, 443) == RouteDecision::Deny {
            return Some(build_empty_reply(
                tx_id,
                rd_bit,
                RCODE_REFUSED,
                question_slice,
            ));
        }

        if qclass != 1 {
            return Some(build_empty_reply(
                tx_id,
                rd_bit,
                RCODE_NOERROR,
                question_slice,
            ));
        }

        match qtype {
            QTYPE_A => {
                let ip = self.allocate_ip(&qname);
                Some(build_a_reply(tx_id, rd_bit, question_slice, ip, 5))
            }
            QTYPE_AAAA => {
                // Return empty NOERROR so dual-stack clients cleanly pick our IPv4 Fake-IP.
                Some(build_empty_reply(
                    tx_id,
                    rd_bit,
                    RCODE_NOERROR,
                    question_slice,
                ))
            }
            _ => Some(build_empty_reply(
                tx_id,
                rd_bit,
                RCODE_NOERROR,
                question_slice,
            )),
        }
    }
}

fn parse_qname(packet: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        if pos >= packet.len() || jumps > 64 {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) != 0 {
            // Unexpected compression pointer in question section
            return None;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
        jumps += 1;
    }
    Some((labels.join("."), pos))
}

fn build_empty_reply(tx_id: [u8; 2], rd_bit: u8, rcode: u16, question: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12 + question.len());
    resp.extend_from_slice(&tx_id);
    resp.push(0x80 | rd_bit); // QR=1, RD copied
    resp.push(0x80 | ((rcode & 0x0F) as u8)); // RA=1, RCODE
    let qdcount: u16 = if question.is_empty() { 0 } else { 1 };
    resp.extend_from_slice(&qdcount.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    resp.extend_from_slice(question);
    resp
}

fn build_a_reply(
    tx_id: [u8; 2],
    rd_bit: u8,
    question: &[u8],
    ip: Ipv4Addr,
    ttl_secs: u32,
) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12 + question.len() + 16);
    resp.extend_from_slice(&tx_id);
    resp.push(0x80 | rd_bit); // QR=1
    resp.push(0x80); // RA=1, NOERROR
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    resp.extend_from_slice(question);
    // Answer: compression pointer to offset 12 (0xC00C)
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&QTYPE_A.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
    resp.extend_from_slice(&ttl_secs.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
    resp.extend_from_slice(&ip.octets());
    resp
}

/// Helper to build a standard DNS A query packet (used in tests and diagnostics).
pub fn build_a_query(tx_id: u16, domain: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in domain.trim_end_matches('.').split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&QTYPE_A.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_fake_ip_and_refuses_denied_host() {
        let mut policy = RoutingPolicy::default();
        policy.inject_hosts.push("api.github.com".into());
        policy.deny_hosts.push("evil.blocked.test".into());
        let dns = FakeIpDns::new(policy);

        let q = build_a_query(0x1234, "api.github.com");
        let resp = dns.handle_query(&q).unwrap();
        assert_eq!(resp[0..2], [0x12, 0x34]);
        assert_eq!(resp[3] & 0x0F, 0); // NOERROR
        let ip = Ipv4Addr::new(
            resp[resp.len() - 4],
            resp[resp.len() - 3],
            resp[resp.len() - 2],
            resp[resp.len() - 1],
        );
        assert!(FakeIpDns::is_fake_ip(ip));
        assert_eq!(dns.lookup_domain(ip).as_deref(), Some("api.github.com"));

        let q_deny = build_a_query(0x5678, "evil.blocked.test");
        let resp_deny = dns.handle_query(&q_deny).unwrap();
        assert_eq!(resp_deny[3] & 0x0F, RCODE_REFUSED as u8);
    }
}
