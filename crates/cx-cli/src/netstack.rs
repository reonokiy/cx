use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use cx_protocol::RouteDecision;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{self, State as TcpState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
    Ipv4Packet, Ipv4Repr, TcpPacket, UdpPacket, UdpRepr,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace};

use crate::dns::FakeIpDns;
use crate::router::TrafficRouter;

/// Abstract L3 raw IP packet I/O allowing the exact same `smoltcp` engine to run over
/// a real Linux kernel `tun_fd` AND an in-memory channel for automated integration tests.
#[async_trait::async_trait]
pub trait AsyncPacketIo: Send + Sync + 'static {
    async fn recv_packet(&self) -> io::Result<Vec<u8>>;
    async fn send_packet(&self, packet: &[u8]) -> io::Result<()>;
}

/// Real Linux `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) asynchronous packet I/O.
pub struct LinuxTunIo {
    fd: AsyncFd<OwnedFd>,
}

impl LinuxTunIo {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        #[allow(deprecated)]
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }
}

#[async_trait::async_trait]
impl AsyncPacketIo for LinuxTunIo {
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let mut buf = vec![0u8; 65536];
            let res = guard.try_io(|inner| {
                let raw_fd = std::os::fd::AsRawFd::as_raw_fd(inner.get_ref());
                let n = unsafe {
                    libc::read(raw_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    buf.truncate(n as usize);
                    Ok(buf.clone())
                }
            });
            match res {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let res = guard.try_io(|inner| {
                let raw_fd = std::os::fd::AsRawFd::as_raw_fd(inner.get_ref());
                let n = unsafe {
                    libc::write(
                        raw_fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match res {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// In-memory L3 packet I/O for end-to-end integration tests without requiring kernel `unshare`.
pub struct ChannelPacketIo {
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl ChannelPacketIo {
    pub fn pair(capacity: usize) -> (Arc<Self>, Arc<Self>) {
        let (a_tx, b_rx) = mpsc::channel(capacity);
        let (b_tx, a_rx) = mpsc::channel(capacity);
        (
            Arc::new(Self {
                rx: tokio::sync::Mutex::new(a_rx),
                tx: a_tx,
            }),
            Arc::new(Self {
                rx: tokio::sync::Mutex::new(b_rx),
                tx: b_tx,
            }),
        )
    }
}

#[async_trait::async_trait]
impl AsyncPacketIo for ChannelPacketIo {
    async fn recv_packet(&self) -> io::Result<Vec<u8>> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "virtual tun closed"))
    }

    async fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.tx
            .send(packet.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual tun closed"))
    }
}

// --- In-memory smoltcp Virtual Device ---

struct VirtualIpDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualIpDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }
}

struct BufRxToken(Vec<u8>);
impl RxToken for BufRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct BufTxToken<'a>(&'a mut VecDeque<Vec<u8>>);
impl<'a> TxToken for BufTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = BufRxToken;
    type TxToken<'a> = BufTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((BufRxToken(pkt), BufTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(BufTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

struct TrackedTcpFlow {
    handle: SocketHandle,
    /// Bytes from `smoltcp` -> handler task (`app_stream`)
    to_app_tx: mpsc::Sender<Vec<u8>>,
    /// Bytes from handler task -> `smoltcp`
    from_app_rx: mpsc::Receiver<Vec<u8>>,
    /// Leftover bytes partially written into `smoltcp` tx buffer
    pending_tx: Vec<u8>,
    app_closed_write: bool,
    peer_closed_write: bool,
}

/// Run the Approach-2 transparent userspace TCP/UDP stack (`smoltcp` + Fake-IP DNS + TLS SNI).
pub async fn run_netstack<P: AsyncPacketIo>(
    packet_io: Arc<P>,
    router: Arc<TrafficRouter>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let dns = Arc::new(FakeIpDns::new(router.policy.clone()));
    let mut device = VirtualIpDevice::new(1500);
    let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
    iface_cfg.random_seed = rand::random();
    let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(10, 200, 0, 1), 24));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 200, 0, 1));

    let mut sockets = SocketSet::new(vec![]);
    let mut flows: HashMap<TcpFlowKey, TrackedTcpFlow> = HashMap::new();
    let wake_notify = Arc::new(Notify::new());

    loop {
        // 1. Poll smoltcp and flush generated IP packets to `tun_fd`.
        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut sockets);
        while let Some(pkt) = device.tx_queue.pop_front() {
            let _ = packet_io.send_packet(&pkt).await;
        }

        // 2. Pump application bytes in/out of tracked smoltcp TCP sockets.
        let mut closed_keys = Vec::new();
        let mut made_progress = false;

        for (&key, flow) in flows.iter_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(flow.handle);

            // smoltcp -> handler task
            while sock.can_recv() {
                if let Ok(permit) = flow.to_app_tx.try_reserve() {
                    let mut buf = vec![0u8; 16 * 1024];
                    match sock.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => {
                            trace!(dst = %key.dst_ip, n, "netstack recv from peer");
                            buf.truncate(n);
                            permit.send(buf);
                            made_progress = true;
                        }
                        _ => break,
                    }
                } else {
                    break;
                }
            }

            // Detect peer FIN (child half-closed write side)
            if !flow.peer_closed_write
                && matches!(
                    sock.state(),
                    TcpState::CloseWait | TcpState::LastAck | TcpState::Closed | TcpState::TimeWait
                )
            {
                flow.peer_closed_write = true;
                // Send empty sentinel to tell pump task to shut down app read half
                let _ = flow.to_app_tx.try_send(Vec::new());
            }

            // handler task -> smoltcp
            while sock.can_send() {
                if flow.pending_tx.is_empty() {
                    match flow.from_app_rx.try_recv() {
                        Ok(data) if !data.is_empty() => {
                            flow.pending_tx = data;
                        }
                        Ok(_) => {
                            flow.app_closed_write = true;
                            sock.close();
                            made_progress = true;
                            break;
                        }
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            flow.app_closed_write = true;
                            sock.close();
                            made_progress = true;
                            break;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                    }
                }
                if !flow.pending_tx.is_empty() {
                    match sock.send_slice(&flow.pending_tx) {
                        Ok(n) if n > 0 => {
                            flow.pending_tx.drain(..n);
                            made_progress = true;
                        }
                        _ => break,
                    }
                }
            }

            if sock.state() == TcpState::Closed
                || (sock.state() == TcpState::TimeWait && flow.app_closed_write)
            {
                closed_keys.push(key);
            }
        }

        for key in closed_keys {
            if let Some(flow) = flows.remove(&key) {
                sockets.remove(flow.handle);
            }
        }

        if made_progress {
            let now2 = SmolInstant::now();
            iface.poll(now2, &mut device, &mut sockets);
            while let Some(pkt) = device.tx_queue.pop_front() {
                let _ = packet_io.send_packet(&pkt).await;
            }
            continue;
        }

        let delay = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()).min(Duration::from_millis(20)))
            .unwrap_or(Duration::from_millis(20));

        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = wake_notify.notified() => {}
            _ = tokio::time::sleep(delay) => {}
            pkt_res = packet_io.recv_packet() => {
                let Ok(pkt) = pkt_res else {
                    break;
                };
                handle_inbound_ip_packet(
                    pkt,
                    &mut device,
                    &mut sockets,
                    &mut flows,
                    &dns,
                    &router,
                    &packet_io,
                    &wake_notify,
                ).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound_ip_packet<P: AsyncPacketIo>(
    pkt: Vec<u8>,
    device: &mut VirtualIpDevice,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<TcpFlowKey, TrackedTcpFlow>,
    dns: &Arc<FakeIpDns>,
    router: &Arc<TrafficRouter>,
    packet_io: &Arc<P>,
    wake_notify: &Arc<Notify>,
) {
    let Ok(ip_pkt) = Ipv4Packet::new_checked(&pkt) else {
        return;
    };
    let src_ip = ip_pkt.src_addr();
    let dst_ip = ip_pkt.dst_addr();

    match ip_pkt.next_header() {
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(ip_pkt.payload()) else {
                return;
            };
            let src_port = udp.src_port();
            let dst_port = udp.dst_port();

            if dst_port == 53 {
                // Intercept ALL UDP *:53 queries (including hardcoded 8.8.8.8:53!)
                if let Some(dns_reply) = dns.handle_query(udp.payload()) {
                    if let Some(reply_ip_pkt) =
                        build_ipv4_udp_packet(dst_ip, dst_port, src_ip, src_port, &dns_reply)
                    {
                        let _ = packet_io.send_packet(&reply_ip_pkt).await;
                    }
                }
                return;
            }

            if dst_port == 443 {
                // Block UDP 443 for Tier 1 inject hosts to force HTTP/3 -> TCP 443 fallback
                if let Some(domain) = dns.lookup_domain(dst_ip) {
                    if router.policy.resolve(&domain, 443) == RouteDecision::Inject {
                        trace!(domain = %domain, "dropped UDP 443 for Tier 1 inject host (forcing TCP fallback)");
                        return;
                    }
                }
            }
        }
        IpProtocol::Tcp => {
            let Ok(tcp_pkt) = TcpPacket::new_checked(ip_pkt.payload()) else {
                return;
            };
            let key = TcpFlowKey {
                src_ip,
                src_port: tcp_pkt.src_port(),
                dst_ip,
                dst_port: tcp_pkt.dst_port(),
            };

            if tcp_pkt.syn() && !tcp_pkt.ack() && !flows.contains_key(&key) {
                let rx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
                let tx_buf = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
                let mut sock = tcp::Socket::new(rx_buf, tx_buf);
                sock.set_timeout(Some(smoltcp::time::Duration::from_secs(30)));
                let listen_ep = IpListenEndpoint {
                    addr: Some(IpAddress::Ipv4(dst_ip)),
                    port: key.dst_port,
                };
                if sock.listen(listen_ep).is_ok() {
                    let handle = sockets.add(sock);
                    let (to_app_tx, to_app_rx) = mpsc::channel::<Vec<u8>>(64);
                    let (from_app_tx, from_app_rx) = mpsc::channel::<Vec<u8>>(64);

                    let app_stream = bridge_channels_to_duplex(
                        to_app_rx,
                        from_app_tx,
                        Arc::clone(wake_notify),
                    );
                    let dns_domain = dns.lookup_domain(dst_ip);
                    debug!(
                        dst_ip = %dst_ip,
                        dst_port = key.dst_port,
                        dns_domain = ?dns_domain,
                        "accepted transparent TCP flow"
                    );

                    let router_clone = Arc::clone(router);
                    tokio::spawn(async move {
                        router_clone
                            .handle_transparent_tcp(app_stream, dst_ip, key.dst_port, dns_domain)
                            .await;
                    });

                    flows.insert(
                        key,
                        TrackedTcpFlow {
                            handle,
                            to_app_tx,
                            from_app_rx,
                            pending_tx: Vec::new(),
                            app_closed_write: false,
                            peer_closed_write: false,
                        },
                    );
                }
            }

            device.rx_queue.push_back(pkt);
        }
        _ => {}
    }
}

fn bridge_channels_to_duplex(
    mut to_app_rx: mpsc::Receiver<Vec<u8>>,
    from_app_tx: mpsc::Sender<Vec<u8>>,
    wake: Arc<Notify>,
) -> DuplexStream {
    let (app_end, stack_end) = tokio::io::duplex(64 * 1024);
    let (mut stack_r, mut stack_w) = tokio::io::split(stack_end);

    let wake_r = Arc::clone(&wake);
    tokio::spawn(async move {
        while let Some(chunk) = to_app_rx.recv().await {
            if chunk.is_empty() {
                let _ = stack_w.shutdown().await;
                break;
            }
            if stack_w.write_all(&chunk).await.is_err() {
                break;
            }
            wake_r.notify_one();
        }
        let _ = stack_w.shutdown().await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stack_r.read(&mut buf).await {
                Ok(0) => {
                    let _ = from_app_tx.send(Vec::new()).await;
                    wake.notify_one();
                    break;
                }
                Ok(n) => {
                    if from_app_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                    wake.notify_one();
                }
                Err(_) => {
                    let _ = from_app_tx.send(Vec::new()).await;
                    wake.notify_one();
                    break;
                }
            }
        }
    });

    app_end
}

pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_repr = UdpRepr {
        src_port,
        dst_port,
    };
    let udp_len = udp_repr.header_len() + payload.len();
    let ip_repr = Ipv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    let total_len = ip_repr.buffer_len() + udp_len;
    let mut buf = vec![0u8; total_len];
    let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
    ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());

    let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
    udp_repr.emit(
        &mut udp_pkt,
        &IpAddress::Ipv4(ip_repr.src_addr),
        &IpAddress::Ipv4(ip_repr.dst_addr),
        payload.len(),
        |dst| dst.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    let _ = IpEndpoint::new(IpAddress::Ipv4(ip_repr.dst_addr), dst_port);
    Some(buf)
}
