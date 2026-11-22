use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cx_protocol::{
    AuthAck, AuthHello, ConnectAck, ConnectMeta, CxGatewayError, PROTOCOL_VERSION, QUIC_ALPN,
    ProtocolError, RequestMeta, StreamType, read_frame, read_stream_type, write_frame,
    write_typed_frame,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt};
use rustls::RootCertStore;
use rustls::server::ResolvesServerCert;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("tls config error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("quic connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("quic connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("quic crypto error: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    #[error("tunnel authentication rejected: {0}")]
    AuthRejected(String),
    #[error("L4 tunnel connect rejected: {0}")]
    L4Rejected(String),
    #[error("invalid extra CA PEM: {0}")]
    InvalidCaPem(String),
}

#[derive(Debug, Clone)]
pub struct QuicTuning {
    pub keep_alive_secs: u64,
    pub max_idle_timeout_secs: u64,
    pub max_concurrent_bidi_streams: u32,
}

impl Default for QuicTuning {
    fn default() -> Self {
        Self {
            keep_alive_secs: 15,
            max_idle_timeout_secs: 60,
            max_concurrent_bidi_streams: 256,
        }
    }
}

fn build_transport_config(tuning: &QuicTuning) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(tuning.keep_alive_secs)));
    if let Ok(idle) = Duration::from_secs(tuning.max_idle_timeout_secs).try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    transport.max_concurrent_bidi_streams(VarInt::from_u32(tuning.max_concurrent_bidi_streams));
    transport.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));
    transport.receive_window(VarInt::from_u32(32 * 1024 * 1024));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(transport)
}

// ============================ CLIENT ============================

#[derive(Debug, Clone, Default)]
pub struct QuicClientTlsOptions {
    /// Optional additional trusted CA certificate(s) in PEM format (dev/self-hosted/tests).
    pub extra_ca_pem: Option<String>,
}

/// Authenticated QUIC client tunnel multiplexing L7 (`0x01`) and L4 (`0x02`) streams.
#[derive(Clone)]
pub struct QuicTunnelClient {
    endpoint: Endpoint,
    connection: Connection,
    /// Hold the control auth stream open for connection lifetime.
    _control_guard: Arc<tokio::sync::Mutex<(SendStream, RecvStream)>>,
}

impl QuicTunnelClient {
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        session_token: &str,
        tls_opts: &QuicClientTlsOptions,
        tuning: &QuicTuning,
    ) -> Result<Self, TunnelError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        if let Some(pem) = &tls_opts.extra_ca_pem {
            let mut reader = BufReader::new(pem.as_bytes());
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TunnelError::InvalidCaPem(e.to_string()))?;
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| TunnelError::InvalidCaPem(e.to_string()))?;
            }
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![QUIC_ALPN.to_vec()];

        let mut client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_cfg)?));
        client_cfg.transport_config(build_transport_config(tuning));

        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_cfg);

        let connection = endpoint.connect(server_addr, server_name)?.await?;

        // Stream 0x00: mandatory control authentication handshake
        let (mut send, mut recv) = connection.open_bi().await?;
        write_typed_frame(
            &mut send,
            StreamType::ControlAuth,
            &AuthHello {
                version: PROTOCOL_VERSION,
                session_token: session_token.to_string(),
            },
        )
        .await?;

        let ack: AuthAck = read_frame(&mut recv).await?;
        if !ack.ok {
            let msg = ack
                .error
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_else(|| "unauthorized".into());
            connection.close(VarInt::from_u32(401), msg.as_bytes());
            return Err(TunnelError::AuthRejected(msg));
        }

        debug!(
            remote = %server_addr,
            session_id = ?ack.session_id,
            "QUIC tunnel authenticated"
        );

        Ok(Self {
            endpoint,
            connection,
            _control_guard: Arc::new(tokio::sync::Mutex::new((send, recv))),
        })
    }

    /// Open a Stream `0x01` L7 HTTP Envelope stream and write `RequestMeta`.
    pub async fn open_l7_stream(
        &self,
        meta: &RequestMeta,
    ) -> Result<(SendStream, RecvStream), TunnelError> {
        let (mut send, recv) = self.connection.open_bi().await?;
        write_typed_frame(&mut send, StreamType::HttpEnvelope, meta).await?;
        Ok((send, recv))
    }

    /// Open a Stream `0x02` L4 Server Passthrough Tunnel stream and wait for `ConnectAck`.
    pub async fn open_l4_stream(
        &self,
        meta: &ConnectMeta,
    ) -> Result<(SendStream, RecvStream), TunnelError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        write_typed_frame(&mut send, StreamType::L4Tunnel, meta).await?;
        let ack: ConnectAck = read_frame(&mut recv).await?;
        if !ack.ok {
            let msg = ack
                .error
                .map(|e| format!("{}: {}", e.code, e.message))
                .unwrap_or_else(|| "connect rejected".into());
            return Err(TunnelError::L4Rejected(msg));
        }
        Ok((send, recv))
    }

    pub fn close(&self) {
        self.connection.close(VarInt::from_u32(0), b"bye");
        self.endpoint.close(VarInt::from_u32(0), b"bye");
    }
}

// ============================ SERVER ============================

#[async_trait::async_trait]
pub trait TunnelHandler: Send + Sync + 'static {
    type Session: Send + Sync + 'static;

    async fn authenticate(&self, hello: AuthHello) -> Result<Arc<Self::Session>, CxGatewayError>;

    async fn handle_l7(
        &self,
        session: Arc<Self::Session>,
        meta: RequestMeta,
        send: SendStream,
        recv: RecvStream,
    );

    async fn handle_l4(
        &self,
        session: Arc<Self::Session>,
        meta: ConnectMeta,
        send: SendStream,
        recv: RecvStream,
    );
}

pub struct QuicTunnelServer {
    endpoint: Endpoint,
}

impl QuicTunnelServer {
    pub fn bind(
        listen_addr: SocketAddr,
        cert_resolver: Arc<dyn ResolvesServerCert>,
        tuning: &QuicTuning,
    ) -> Result<Self, TunnelError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);
        tls_cfg.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        tls_cfg.max_early_data_size = 0; // disable 0-RTT replay risk on mutating requests

        let mut server_cfg =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_cfg)?));
        server_cfg.transport_config(build_transport_config(tuning));

        let endpoint = Endpoint::server(server_cfg, listen_addr)?;
        info!(listen = %endpoint.local_addr()?, "QUIC data-plane server bound");
        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.endpoint.local_addr()
    }

    pub async fn serve<H: TunnelHandler>(self, handler: Arc<H>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        handle_connection(conn, handler).await;
                    }
                    Err(err) => {
                        warn!(error = %err, "QUIC incoming handshake failed");
                    }
                }
            });
        }
    }
}

async fn handle_connection<H: TunnelHandler>(conn: Connection, handler: Arc<H>) {
    let remote = conn.remote_address();

    // First stream MUST be 0x00 ControlAuth.
    let Ok((mut auth_send, mut auth_recv)) = conn.accept_bi().await else {
        return;
    };

    let session = match read_stream_type(&mut auth_recv).await {
        Ok(StreamType::ControlAuth) => match read_frame::<_, AuthHello>(&mut auth_recv).await {
            Ok(hello) => match handler.authenticate(hello).await {
                Ok(session) => {
                    let _ = write_frame(
                        &mut auth_send,
                        &AuthAck {
                            ok: true,
                            session_id: None,
                            expires_at: None,
                            error: None,
                        },
                    )
                    .await;
                    session
                }
                Err(err) => {
                    let _ = write_frame(
                        &mut auth_send,
                        &AuthAck {
                            ok: false,
                            session_id: None,
                            expires_at: None,
                            error: Some(err.clone()),
                        },
                    )
                    .await;
                    conn.close(VarInt::from_u32(401), err.message.as_bytes());
                    return;
                }
            },
            Err(err) => {
                warn!(remote = %remote, error = %err, "malformed AuthHello");
                conn.close(VarInt::from_u32(400), b"malformed auth");
                return;
            }
        },
        _ => {
            warn!(remote = %remote, "first QUIC stream was not ControlAuth (0x00)");
            conn.close(VarInt::from_u32(401), b"auth stream required first");
            return;
        }
    };

    // Keep control stream held while accepting concurrent data streams.
    let _ctrl = (auth_send, auth_recv);

    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(err) => {
                debug!(remote = %remote, error = %err, "QUIC connection closed");
                break;
            }
        };

        let handler = Arc::clone(&handler);
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            match read_stream_type(&mut recv).await {
                Ok(StreamType::HttpEnvelope) => {
                    match read_frame::<_, RequestMeta>(&mut recv).await {
                        Ok(meta) => handler.handle_l7(session, meta, send, recv).await,
                        Err(err) => warn!(error = %err, "failed to read L7 RequestMeta"),
                    }
                }
                Ok(StreamType::L4Tunnel) => {
                    match read_frame::<_, ConnectMeta>(&mut recv).await {
                        Ok(meta) => handler.handle_l4(session, meta, send, recv).await,
                        Err(err) => warn!(error = %err, "failed to read L4 ConnectMeta"),
                    }
                }
                Ok(StreamType::ControlAuth) => {
                    warn!("unexpected duplicate ControlAuth stream");
                }
                Err(err) => {
                    warn!(error = %err, "failed to read stream type byte");
                }
            }
        });
    }
}
