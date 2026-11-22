use std::ffi::CString;
use std::fs;
use std::io::{self, IoSlice, IoSliceMut};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{Context, bail};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd::{getgid, getuid};

// Linux TUN ioctl constants
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

pub fn create_bootstrap_socketpair() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::empty(),
    )
    .context("failed to create unix socketpair for netns bootstrap")?;
    Ok((parent, child))
}

/// Parent side: receive `tun_fd` from `__netns-init` child via `SCM_RIGHTS`.
pub fn recv_tun_fd(parent_sock: RawFd) -> anyhow::Result<OwnedFd> {
    let mut data = [0u8; 16];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_buf = nix::cmsg_space!(RawFd);

    let msg = recvmsg::<()>(parent_sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())
        .context("failed to receive tun_fd from __netns-init")?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    bail!("__netns-init closed socket without sending tun_fd (userns or /dev/net/tun may be blocked)");
}

/// Parent side: signal child that `smoltcp` + DNS stack is ready to accept packets.
pub fn send_ready_ack(parent_sock: RawFd) -> anyhow::Result<()> {
    let buf = [b'R'];
    let iov = [IoSlice::new(&buf)];
    sendmsg::<()>(parent_sock, &iov, &[], MsgFlags::empty(), None)
        .context("failed sending READY ack to __netns-init")?;
    Ok(())
}

/// Executed inside single-threaded `/proc/self/exe __netns-init` BEFORE any async runtime starts.
/// Sets up `CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS`, `cx0` TUN, Netlink routes,
/// private `/etc/resolv.conf` & `/etc/nsswitch.conf`, passes `tun_fd` to parent, and `execvp`s target!
pub fn run_netns_init(
    sock_fd: RawFd,
    resolv_path: &Path,
    nsswitch_path: &Path,
    cmd: &[String],
) -> anyhow::Result<()> {
    if cmd.is_empty() {
        bail!("missing command for __netns-init");
    }

    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    // 1. Create unprivileged User + Network + Mount namespaces
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)
        .context("unshare(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS) failed")?;

    // 2. Map original UID/GID 1:1 (preserves file permissions; execvp auto-drops caps when uid != 0)
    fs::write("/proc/self/setgroups", b"deny")
        .context("failed writing /proc/self/setgroups")?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .context("failed writing /proc/self/uid_map (check AppArmor unprivileged userns policy)")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .context("failed writing /proc/self/gid_map")?;

    // 3. Open /dev/net/tun and create `cx0`
    let tun_fd = open_tun_device("cx0")?;

    // 4. Bring up `lo` + `cx0` (10.200.0.2/24, MTU 1500) + default route via pure-Rust Netlink
    configure_netns_interfaces("cx0", Ipv4Addr::new(10, 200, 0, 2), 24, 1500)?;

    // 5. Private mount namespace: override /etc/resolv.conf & /etc/nsswitch.conf (blocks systemd-resolved D-Bus bypass)
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to make mount tree private")?;

    bind_mount_readonly(resolv_path, Path::new("/etc/resolv.conf"))?;
    bind_mount_readonly(nsswitch_path, Path::new("/etc/nsswitch.conf"))?;

    // 6. Pass `tun_fd` to parent over `SCM_RIGHTS`
    let tag = [b'T'];
    let iov = [IoSlice::new(&tag)];
    let fds = [tun_fd.as_raw_fd()];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(sock_fd, &iov, &cmsgs, MsgFlags::empty(), None)
        .context("failed sending tun_fd via SCM_RIGHTS")?;

    // 7. Wait for parent READY signal
    let mut ack = [0u8; 4];
    let mut ack_iov = [IoSliceMut::new(&mut ack)];
    recvmsg::<()>(sock_fd, &mut ack_iov, None, MsgFlags::empty())
        .context("failed waiting for parent READY ack")?;

    // 8. Close internal bootstrap FDs so target CLI never sees them
    drop(tun_fd);
    unsafe {
        libc::close(sock_fd);
    }

    // 9. Replace process image with target CLI (UID != 0 -> kernel strips all namespace capabilities)
    let c_prog = CString::new(cmd[0].as_str())?;
    let c_args: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()?;
    match nix::unistd::execvp(&c_prog, &c_args) {
        Ok(infallible) => match infallible {},
        Err(e) => Err(e).with_context(|| format!("execvp('{}') failed", cmd[0])),
    }
}

fn open_tun_device(name: &str) -> anyhow::Result<OwnedFd> {
    let path = CString::new("/dev/net/tun")?;
    let raw_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error()).context("failed to open /dev/net/tun");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut req = IfReq {
        ifr_name: [0u8; libc::IFNAMSIZ],
        ifr_flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };
    let bytes = name.as_bytes();
    let copy_len = bytes.len().min(libc::IFNAMSIZ - 1);
    req.ifr_name[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut req) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("ioctl(TUNSETIFF) failed");
    }
    Ok(fd)
}

fn bind_mount_readonly(src: &Path, dst: &Path) -> anyhow::Result<()> {
    // Follow symlinks (e.g. /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf)
    let target = fs::canonicalize(dst).unwrap_or_else(|_| dst.to_path_buf());
    mount(
        Some(src),
        &target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "bind mount {} -> {} failed",
            src.display(),
            target.display()
        )
    })?;
    let _ = mount(
        None::<&str>,
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    );
    Ok(())
}

// --- Pure-Rust Minimal Linux Netlink (`NETLINK_ROUTE`) Interface & Route Config ---

fn configure_netns_interfaces(
    tun_name: &str,
    tun_ip: Ipv4Addr,
    prefix_len: u8,
    mtu: u32,
) -> anyhow::Result<()> {
    let lo_idx = if_nametoindex("lo")?;
    let tun_idx = if_nametoindex(tun_name)?;

    let nl_fd = unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("failed to open AF_NETLINK socket");
        }
        OwnedFd::from_raw_fd(fd)
    };

    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    let bind_rc = unsafe {
        libc::bind(
            nl_fd.as_raw_fd(),
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bind_rc < 0 {
        return Err(io::Error::last_os_error()).context("netlink bind failed");
    }

    // 1. Bring `lo` UP
    nl_set_link_up(nl_fd.as_raw_fd(), lo_idx, None, 1)?;
    // 2. Add 10.200.0.2/24 to `cx0`
    nl_add_ipv4_addr(nl_fd.as_raw_fd(), tun_idx, tun_ip, prefix_len, 2)?;
    // 3. Bring `cx0` UP with MTU 1500
    nl_set_link_up(nl_fd.as_raw_fd(), tun_idx, Some(mtu), 3)?;
    // 4. Add default route 0.0.0.0/0 dev cx0
    nl_add_default_ipv4_route(nl_fd.as_raw_fd(), tun_idx, 4)?;
    Ok(())
}

fn if_nametoindex(name: &str) -> anyhow::Result<u32> {
    let c = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("if_nametoindex('{name}') failed"));
    }
    Ok(idx)
}

fn nl_append_attr(buf: &mut Vec<u8>, rta_type: u16, data: &[u8]) {
    let rta_len = (4 + data.len()) as u16;
    buf.extend_from_slice(&rta_len.to_ne_bytes());
    buf.extend_from_slice(&rta_type.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

fn nl_send_and_ack(fd: RawFd, msg_type: u16, flags: u16, seq: u32, body: &[u8]) -> anyhow::Result<()> {
    let total_len = (16 + body.len()) as u32;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(&total_len.to_ne_bytes());
    pkt.extend_from_slice(&msg_type.to_ne_bytes());
    pkt.extend_from_slice(&(flags | (libc::NLM_F_REQUEST as u16) | (libc::NLM_F_ACK as u16)).to_ne_bytes());
    pkt.extend_from_slice(&seq.to_ne_bytes());
    pkt.extend_from_slice(&0u32.to_ne_bytes()); // pid=0 (kernel)
    pkt.extend_from_slice(body);

    let sent = unsafe { libc::send(fd, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error()).context("netlink send failed");
    }

    let mut resp = [0u8; 4096];
    let n = unsafe { libc::recv(fd, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
    if n < 20 {
        return Err(io::Error::last_os_error()).context("netlink recv ack failed");
    }
    let nlmsg_type = u16::from_ne_bytes([resp[4], resp[5]]);
    if nlmsg_type == libc::NLMSG_ERROR as u16 {
        let err_code = i32::from_ne_bytes([resp[16], resp[17], resp[18], resp[19]]);
        if err_code != 0 {
            let io_err = io::Error::from_raw_os_error(-err_code);
            return Err(io_err).with_context(|| format!("netlink msg {msg_type} returned error"));
        }
    }
    Ok(())
}

fn nl_set_link_up(fd: RawFd, ifindex: u32, mtu: Option<u32>, seq: u32) -> anyhow::Result<()> {
    // struct ifinfomsg (16 bytes)
    let mut body = vec![0u8; 16];
    body[0] = libc::AF_UNSPEC as u8;
    body[4..8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    let up = libc::IFF_UP as u32;
    body[8..12].copy_from_slice(&up.to_ne_bytes()); // ifi_flags
    body[12..16].copy_from_slice(&up.to_ne_bytes()); // ifi_change
    if let Some(m) = mtu {
        const IFLA_MTU: u16 = 4;
        nl_append_attr(&mut body, IFLA_MTU, &m.to_ne_bytes());
    }
    nl_send_and_ack(fd, libc::RTM_NEWLINK, 0, seq, &body)
}

fn nl_add_ipv4_addr(
    fd: RawFd,
    ifindex: u32,
    ip: Ipv4Addr,
    prefix_len: u8,
    seq: u32,
) -> anyhow::Result<()> {
    // struct ifaddrmsg (8 bytes)
    let mut body = vec![0u8; 8];
    body[0] = libc::AF_INET as u8;
    body[1] = prefix_len;
    body[2] = 0; // flags
    body[3] = 0; // RT_SCOPE_UNIVERSE
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());

    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    nl_append_attr(&mut body, IFA_LOCAL, &ip.octets());
    nl_append_attr(&mut body, IFA_ADDRESS, &ip.octets());

    let flags = (libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    nl_send_and_ack(fd, libc::RTM_NEWADDR, flags, seq, &body)
}

fn nl_add_default_ipv4_route(fd: RawFd, oif_index: u32, seq: u32) -> anyhow::Result<()> {
    // struct rtmsg (12 bytes)
    let mut body = vec![0u8; 12];
    body[0] = libc::AF_INET as u8; // rtm_family
    body[1] = 0; // rtm_dst_len = 0 (default 0.0.0.0/0)
    body[2] = 0; // rtm_src_len
    body[3] = 0; // rtm_tos
    body[4] = libc::RT_TABLE_MAIN;
    body[5] = libc::RTPROT_BOOT;
    body[6] = libc::RT_SCOPE_UNIVERSE;
    body[7] = libc::RTN_UNICAST;

    const RTA_OIF: u16 = 4;
    nl_append_attr(&mut body, RTA_OIF, &oif_index.to_ne_bytes());

    let flags = (libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16;
    nl_send_and_ack(fd, libc::RTM_NEWROUTE, flags, seq, &body)
}

/// Diagnostic probe for `cx doctor`.
#[derive(Debug)]
pub struct NetnsDiagnostic {
    pub tun_accessible: bool,
    pub apparmor_restrict_userns: bool,
    pub unshare_works: bool,
    pub details: String,
}

/// Single-threaded self-probe executed via `/proc/self/exe __netns-probe`.
/// Probing inside `cx` itself (rather than `/usr/bin/unshare`) accurately reflects
/// per-binary AppArmor profiles installed specifically for `cx`.
pub fn run_netns_probe() -> anyhow::Result<()> {
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS)
        .context("unshare(CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS) failed")?;
    fs::write("/proc/self/setgroups", b"deny")
        .context("failed writing /proc/self/setgroups")?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .context("failed writing /proc/self/uid_map")?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .context("failed writing /proc/self/gid_map")?;
    let _tun = open_tun_device("cxprobe0")?;
    Ok(())
}

pub fn diagnose_netns() -> NetnsDiagnostic {
    let tun_accessible = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .is_ok();

    let apparmor_restrict_userns = fs::read_to_string(
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    )
    .map(|s| s.trim() == "1")
    .unwrap_or(false);

    // Probe via `cx __netns-probe` so per-binary AppArmor profiles for `cx` are detected accurately.
    let probe = std::env::current_exe()
        .map_err(io::Error::other)
        .and_then(|exe| {
            std::process::Command::new(exe)
                .arg("__netns-probe")
                .output()
        });
    let (unshare_works, details) = match probe {
        Ok(out) if out.status.success() => {
            (true, "unprivileged user+net+mount namespace + tun OK".into())
        }
        Ok(out) => (
            false,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ),
        Err(e) => (false, e.to_string()),
    };

    NetnsDiagnostic {
        tun_accessible,
        apparmor_restrict_userns,
        unshare_works,
        details,
    }
}
