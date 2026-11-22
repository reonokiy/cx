use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, bail};
use cx_crypto::{EphemeralCa, generate_random_token};
use cx_protocol::{CreateSessionResponse, GitRewriteRule};
use cx_tunnel::{QuicClientTlsOptions, QuicTuning, QuicTunnelClient};
use tokio::net::lookup_host;
use tokio::process::Command;
use tracing::{info, warn};

use crate::netns::{create_bootstrap_socketpair, diagnose_netns, recv_tun_fd, send_ready_ack};
use crate::netstack::{LinuxTunIo, run_netstack};
use crate::proxy_fallback::LocalFallbackProxy;
use crate::router::TrafficRouter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptMode {
    /// Approach 2 (Primary): Linux Rootless NetNS + `cx0` TUN + `smoltcp` + Fake-IP + SNI
    Netns,
    /// Fallback: Local HTTP CONNECT proxy (for restricted containers / AppArmor without userns)
    Proxy,
    /// Use NetNS when permitted by kernel/AppArmor, else warn & fall back to Proxy
    Auto,
}

/// Drop guard deleting temporary tmpfs files (`ca.pem`, `resolv.conf`, `nsswitch.conf`).
struct TempRuntimeDir {
    dir: PathBuf,
}

impl TempRuntimeDir {
    fn create() -> anyhow::Result<Self> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/cx-{}", nix::unistd::getuid())));
        let dir = base.join("cx").join(format!(
            "sess-{}-{}",
            std::process::id(),
            generate_random_token("", 8)
        ));
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self { dir })
    }

    fn write_private(&self, filename: &str, content: &str) -> anyhow::Result<PathBuf> {
        let path = self.dir.join(filename);
        fs::write(&path, content)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }
}

impl Drop for TempRuntimeDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub async fn execute_command(
    session: &CreateSessionResponse,
    quic_ca_pem: Option<String>,
    mode: InterceptMode,
    cmd: &[String],
) -> anyhow::Result<i32> {
    if cmd.is_empty() {
        bail!("no command provided after `--`");
    }

    let effective_mode = match mode {
        InterceptMode::Netns => InterceptMode::Netns,
        InterceptMode::Proxy => InterceptMode::Proxy,
        InterceptMode::Auto => {
            let diag = diagnose_netns();
            if diag.tun_accessible && diag.unshare_works {
                InterceptMode::Netns
            } else {
                warn!(
                    reason = %diag.details,
                    "unprivileged netns unavailable on this host; falling back to --mode proxy (run `cx doctor` for AppArmor fix)"
                );
                InterceptMode::Proxy
            }
        }
    };

    // 1. Connect QUIC data plane on Host NetNS
    let quic_addr = resolve_socket_addr(&session.quic_endpoint).await?;
    let tunnel = QuicTunnelClient::connect(
        quic_addr,
        &session.quic_server_name,
        &session.session_token,
        &QuicClientTlsOptions {
            extra_ca_pem: quic_ca_pem,
        },
        &QuicTuning::default(),
    )
    .await
    .with_context(|| format!("failed to connect QUIC tunnel at {}", session.quic_endpoint))?;

    // 2. Generate ephemeral P-256 Root CA and write tmpfs CA files
    let ca = Arc::new(EphemeralCa::generate()?);
    let runtime_dir = TempRuntimeDir::create()?;
    let merged_ca_path = runtime_dir.write_private("ca-bundle.pem", &ca.build_merged_system_ca_bundle())?;
    let extra_ca_path = runtime_dir.write_private("ca-extra.pem", ca.ca_pem())?;

    let router = Arc::new(TrafficRouter {
        policy: session.routing.clone(),
        profile: session.profile.clone(),
        ca,
        tunnel: tunnel.clone(),
        direct_overrides: Arc::new(BTreeMap::new()),
    });

    // 3. Prepare base sanitized child environment
    let mut child_env = build_child_env(
        &merged_ca_path,
        &extra_ca_path,
        &session.client.env_inject,
        &session.client.git_rewrites,
    );

    let exit_code = match effective_mode {
        InterceptMode::Netns => {
            run_with_netns(router, &runtime_dir, &child_env, cmd).await?
        }
        InterceptMode::Proxy => {
            let nonce = generate_random_token("", 24);
            let proxy = LocalFallbackProxy::start(router, &nonce).await?;
            let proxy_url = format!("http://cx:{nonce}@{}", proxy.addr);
            for k in [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ] {
                child_env.insert(k.into(), proxy_url.clone());
            }
            child_env.insert("NO_PROXY".into(), "127.0.0.1,::1,localhost".into());
            child_env.insert("no_proxy".into(), "127.0.0.1,::1,localhost".into());

            run_child_process(&cmd[0], &cmd[1..], &child_env).await?
        }
        InterceptMode::Auto => unreachable!(),
    };

    tunnel.close();
    Ok(exit_code)
}

async fn run_with_netns(
    router: Arc<TrafficRouter>,
    runtime_dir: &TempRuntimeDir,
    child_env: &BTreeMap<String, String>,
    cmd: &[String],
) -> anyhow::Result<i32> {
    let resolv_path = runtime_dir.write_private(
        "resolv.conf",
        "nameserver 10.200.0.1\noptions edns0 single-request\n",
    )?;
    let nsswitch_content = build_clean_nsswitch();
    let nsswitch_path = runtime_dir.write_private("nsswitch.conf", &nsswitch_content)?;

    let (parent_sock, child_sock) = create_bootstrap_socketpair()?;
    let child_sock_raw = child_sock.as_raw_fd();

    // Ensure child_sock stays open across exec of `/proc/self/exe` (clear FD_CLOEXEC)
    unsafe {
        let flags = libc::fcntl(child_sock_raw, libc::F_GETFD);
        libc::fcntl(child_sock_raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    let self_exe = std::env::current_exe().context("cannot locate current cx executable")?;
    let mut c = Command::new(self_exe);
    c.arg("__netns-init")
        .arg("--sock-fd")
        .arg(child_sock_raw.to_string())
        .arg("--resolv")
        .arg(&resolv_path)
        .arg("--nsswitch")
        .arg(&nsswitch_path)
        .arg("--")
        .args(cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_clear()
        .envs(child_env);

    let mut child = c.spawn().context("failed to spawn __netns-init helper")?;
    drop(child_sock); // parent does not need child's socket end

    // Receive `tun_fd` from isolated netns helper via `SCM_RIGHTS`
    let parent_raw = parent_sock.as_raw_fd();
    let tun_fd = tokio::task::spawn_blocking(move || recv_tun_fd(parent_raw))
        .await??;

    // Start `smoltcp` userspace stack on `tun_fd` BEFORE releasing child to `execvp`
    let tun_io = Arc::new(LinuxTunIo::new(tun_fd)?);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let netstack_task = tokio::spawn(run_netstack(tun_io, router, shutdown_rx));

    // Tell helper we are ready; helper closes bootstrap FDs and execvp's the real CLI!
    send_ready_ack(parent_sock.as_raw_fd())?;
    drop(parent_sock);
    info!("Rootless NetNS transparent stack active");

    let status = wait_child_forwarding_signals(&mut child).await?;
    let _ = shutdown_tx.send(true);
    let _ = netstack_task.await;

    Ok(exit_status_to_code(status))
}

async fn run_child_process(
    program: &str,
    args: &[String],
    child_env: &BTreeMap<String, String>,
) -> anyhow::Result<i32> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_clear()
        .envs(child_env)
        .spawn()
        .with_context(|| format!("failed to spawn '{program}'"))?;

    let status = wait_child_forwarding_signals(&mut child).await?;
    Ok(exit_status_to_code(status))
}

async fn wait_child_forwarding_signals(
    child: &mut tokio::process::Child,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = tokio::signal::ctrl_c() => {
                if let Some(pid) = child.id() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGINT,
                    );
                }
            }
            _ = sigterm.recv() => {
                if let Some(pid) = child.id() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGTERM,
                    );
                }
            }
        }
    }
}

fn exit_status_to_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

/// Sanitize parent environment (stripping `CX_*` auth vars!) and inject CA + virtual key + git rewrite.
fn build_child_env(
    merged_ca_path: &Path,
    extra_ca_path: &Path,
    env_inject: &BTreeMap<String, String>,
    git_rewrites: &[GitRewriteRule],
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars()
        .filter(|(k, _)| !is_sensitive_cx_env(k))
        .collect();

    let ca_str = merged_ca_path.display().to_string();
    for k in [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "REQUESTS_CA_BUNDLE",
        "PIP_CERT",
        "AWS_CA_BUNDLE",
        "CARGO_HTTP_CAINFO",
        "DENO_CERT",
    ] {
        env.insert(k.into(), ca_str.clone());
    }
    env.insert(
        "NODE_EXTRA_CA_CERTS".into(),
        extra_ca_path.display().to_string(),
    );

    for (k, v) in env_inject {
        env.insert(k.clone(), v.clone());
    }

    // Declarative git HTTPS rewrite + virtual credential helper via GIT_CONFIG_COUNT
    if !git_rewrites.is_empty() {
        let mut count: usize = env
            .get("GIT_CONFIG_COUNT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let self_exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "cx".into());

        for rule in git_rewrites {
            for from_prefix in &rule.from {
                env.insert(
                    format!("GIT_CONFIG_KEY_{count}"),
                    format!("url.https://{}/.insteadOf", rule.host),
                );
                env.insert(format!("GIT_CONFIG_VALUE_{count}"), from_prefix.clone());
                count += 1;
            }
            env.insert(
                format!("GIT_CONFIG_KEY_{count}"),
                format!("credential.https://{}.helper", rule.host),
            );
            env.insert(
                format!("GIT_CONFIG_VALUE_{count}"),
                format!("!{self_exe} git-credential"),
            );
            count += 1;

            env.insert("CX_GIT_CRED_USER".into(), rule.credential_username.clone());
            env.insert("CX_GIT_CRED_VKEY".into(), rule.virtual_key.clone());
        }
        env.insert("GIT_CONFIG_COUNT".into(), count.to_string());
    }

    env
}

fn is_sensitive_cx_env(key: &str) -> bool {
    let up = key.to_ascii_uppercase();
    up.starts_with("CX_") && !up.starts_with("CX_GIT_CRED_")
}

fn build_clean_nsswitch() -> String {
    let mut out = String::new();
    let mut saw_hosts = false;
    if let Ok(raw) = fs::read_to_string("/etc/nsswitch.conf") {
        for line in raw.lines() {
            if line.trim_start().starts_with("hosts:") {
                out.push_str("hosts: files dns\n");
                saw_hosts = true;
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if !saw_hosts {
        out.push_str("hosts: files dns\n");
    }
    out
}

async fn resolve_socket_addr(endpoint: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(sa) = endpoint.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut addrs = lookup_host(endpoint).await?;
    addrs
        .next()
        .with_context(|| format!("could not resolve QUIC endpoint '{endpoint}'"))
}
