use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const QUIC_ALPN: &[u8] = b"cx-quic/1";
pub const MAX_META_FRAME_LEN: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json codec error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("metadata frame too large: {0} bytes (max {MAX_META_FRAME_LEN})")]
    FrameTooLarge(usize),
    #[error("unknown stream type: 0x{0:02x}")]
    UnknownStreamType(u8),
}

/// First byte of every QUIC bidirectional stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    /// Control & authentication handshake stream (must be opened first).
    ControlAuth = 0x00,
    /// L7 HTTP envelope stream (Tier 1 inject & Tier 2b server_http_passthrough).
    HttpEnvelope = 0x01,
    /// L4 raw TCP/TLS passthrough tunnel stream (Tier 2a server_tunnel).
    L4Tunnel = 0x02,
}

impl TryFrom<u8> for StreamType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::ControlAuth),
            0x01 => Ok(Self::HttpEnvelope),
            0x02 => Ok(Self::L4Tunnel),
            other => Err(ProtocolError::UnknownStreamType(other)),
        }
    }
}

pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(msg)?;
    if payload.len() > MAX_META_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, ProtocolError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_META_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

pub async fn write_typed_frame<W, T>(
    writer: &mut W,
    stream_type: StreamType,
    msg: &T,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    writer.write_all(&[stream_type as u8]).await?;
    write_frame(writer, msg).await
}

pub async fn read_stream_type<R>(reader: &mut R) -> Result<StreamType, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut b = [0u8; 1];
    reader.read_exact(&mut b).await?;
    StreamType::try_from(b[0])
}

// --- Stream 0x00: Auth & Control ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthHello {
    pub version: u16,
    pub session_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAck {
    pub ok: bool,
    pub session_id: Option<String>,
    pub expires_at: Option<i64>,
    pub error: Option<CxGatewayError>,
}

// --- Stream 0x01: L7 HTTP Envelope ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    pub request_id: String,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    /// Ordered HTTP headers preserving exact names and multi-values.
    pub headers: Vec<(String, Vec<u8>)>,
    pub profile_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub cx_error: Option<CxGatewayError>,
}

// --- Stream 0x02: L4 Server Tunnel ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectMeta {
    pub host: String,
    pub port: u16,
    pub profile_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectAck {
    pub ok: bool,
    pub error: Option<CxGatewayError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CxGatewayError {
    pub code: String,
    pub message: String,
}

impl CxGatewayError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

// --- 3-Tier Routing Policy ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultRouteAction {
    ClientPassthrough,
    Deny,
}

impl Default for DefaultRouteAction {
    fn default() -> Self {
        Self::ClientPassthrough
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecision {
    Deny,
    Inject,
    ServerTunnel,
    ServerHttpPassthrough,
    ClientPassthrough,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingPolicy {
    #[serde(default)]
    pub deny_hosts: Vec<String>,
    #[serde(default)]
    pub inject_hosts: Vec<String>,
    #[serde(default)]
    pub server_tunnel_hosts: Vec<String>,
    #[serde(default)]
    pub server_tunnel_ports: Vec<u16>,
    #[serde(default)]
    pub server_http_passthrough_hosts: Vec<String>,
    #[serde(default)]
    pub default_action: DefaultRouteAction,
}

impl RoutingPolicy {
    /// Deterministic 3-tier match:
    /// 0. deny -> 1. inject -> 2a. server_tunnel -> 2b. server_http_passthrough -> 3. default_action
    pub fn resolve(&self, host: &str, port: u16) -> RouteDecision {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        if self
            .deny_hosts
            .iter()
            .any(|p| host_matches_pattern(&host_lc, p))
        {
            return RouteDecision::Deny;
        }
        if self
            .inject_hosts
            .iter()
            .any(|p| host_matches_pattern(&host_lc, p))
        {
            return RouteDecision::Inject;
        }
        let port_ok = self.server_tunnel_ports.is_empty() || self.server_tunnel_ports.contains(&port);
        if port_ok
            && self
                .server_tunnel_hosts
                .iter()
                .any(|p| host_matches_pattern(&host_lc, p))
        {
            return RouteDecision::ServerTunnel;
        }
        if self
            .server_http_passthrough_hosts
            .iter()
            .any(|p| host_matches_pattern(&host_lc, p))
        {
            return RouteDecision::ServerHttpPassthrough;
        }
        match self.default_action {
            DefaultRouteAction::ClientPassthrough => RouteDecision::ClientPassthrough,
            DefaultRouteAction::Deny => RouteDecision::Deny,
        }
    }
}

/// Exact hostname or single-level leftmost wildcard (`*.example.com`).
pub fn host_matches_pattern(host_lowercase: &str, pattern: &str) -> bool {
    let pat = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pat.strip_prefix("*.") {
        // Must match at least one subdomain label before `.suffix`
        if let Some(prefix) = host_lowercase.strip_suffix(suffix) {
            return prefix.ends_with('.') && prefix.len() > 1;
        }
        false
    } else {
        host_lowercase == pat
    }
}

// --- Client Launch Instructions (Served Dynamically from Plugins) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRewriteRule {
    pub host: String,
    pub from: Vec<String>,
    pub credential_username: String,
    pub virtual_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientLaunchSpec {
    pub env_inject: BTreeMap<String, String>,
    pub git_rewrites: Vec<GitRewriteRule>,
}

// --- Control Plane REST DTOs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliLoginStartResponse {
    pub login_id: String,
    pub user_code: String,
    pub poll_secret: String,
    pub verification_url: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliLoginPollRequest {
    pub login_id: String,
    pub poll_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliLoginPollResponse {
    /// "pending" | "approved" | "expired"
    pub status: String,
    pub access_token: Option<String>,
    pub user: Option<UserSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePlatformSummary {
    pub id: String,
    pub provider_id: String,
    pub inject_hosts: Vec<String>,
    pub server_tunnel_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub platforms: Vec<ProfilePlatformSummary>,
    pub inject_hosts: Vec<String>,
    pub server_tunnel_hosts: Vec<String>,
    pub default_action: DefaultRouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub session_token: String,
    pub expires_at: i64,
    pub quic_endpoint: String,
    pub quic_server_name: String,
    pub profile: String,
    pub routing: RoutingPolicy,
    pub client: ClientLaunchSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScopedTokenRequest {
    pub name: String,
    pub profiles: Vec<String>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScopedTokenResponse {
    pub id: String,
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVirtualKeyRequest {
    pub profile: String,
    /// Platform binding ID within the profile (auto-inferred if the profile has exactly one platform).
    #[serde(default)]
    pub platform: Option<String>,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVirtualKeyResponse {
    pub id: String,
    pub virtual_key: String,
    pub profile: String,
    pub platform: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSecretRequest {
    pub name: String,
    pub scope: String, // "shared" | "personal"
    pub fields: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_precedence_works() {
        let policy = RoutingPolicy {
            deny_hosts: vec!["blocked.github.com".into()],
            inject_hosts: vec!["api.github.com".into(), "github.com".into()],
            server_tunnel_hosts: vec!["*.githubusercontent.com".into()],
            server_tunnel_ports: vec![443],
            server_http_passthrough_hosts: vec!["status.github.com".into()],
            default_action: DefaultRouteAction::ClientPassthrough,
        };

        assert_eq!(policy.resolve("blocked.github.com", 443), RouteDecision::Deny);
        assert_eq!(policy.resolve("API.GITHUB.COM.", 443), RouteDecision::Inject);
        assert_eq!(
            policy.resolve("objects.githubusercontent.com", 443),
            RouteDecision::ServerTunnel
        );
        // Port mismatch falls through to default
        assert_eq!(
            policy.resolve("objects.githubusercontent.com", 80),
            RouteDecision::ClientPassthrough
        );
        // Bare apex must NOT match `*.githubusercontent.com`
        assert_eq!(
            policy.resolve("githubusercontent.com", 443),
            RouteDecision::ClientPassthrough
        );
        assert_eq!(
            policy.resolve("status.github.com", 443),
            RouteDecision::ServerHttpPassthrough
        );
        assert_eq!(
            policy.resolve("example.org", 443),
            RouteDecision::ClientPassthrough
        );
    }
}
