use std::os::fd::RawFd;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use cx_cli::commands::{
    cmd_doctor, cmd_exec, cmd_git_credential, cmd_key_create, cmd_login, cmd_profile_list,
    cmd_token_create, cmd_whoami,
};
use cx_cli::netns::{run_netns_init, run_netns_probe};
use cx_cli::runner::InterceptMode;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cx",
    version,
    about = "Secretless CLI credential-injecting proxy (Linux Rootless NetNS + QUIC)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Netns,
    Proxy,
    Auto,
}

impl From<ModeArg> for InterceptMode {
    fn from(v: ModeArg) -> Self {
        match v {
            ModeArg::Netns => InterceptMode::Netns,
            ModeArg::Proxy => InterceptMode::Proxy,
            ModeArg::Auto => InterceptMode::Auto,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Sign in to cx-server via external OIDC (or --token for PAT/dev)
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: Option<String>,
        /// Optional CA PEM file for self-signed dev QUIC certificates
        #[arg(long)]
        quic_ca: Option<PathBuf>,
        #[arg(long)]
        default_profile: Option<String>,
    },
    /// Show currently authenticated OIDC identity
    Whoami,
    /// List available profiles
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage static placeholder virtual keys
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Manage scoped access tokens (for CI / automation)
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Execute a command with transparent secretless credential injection
    Exec {
        #[arg(short, long)]
        profile: Option<String>,
        /// Traffic interception mode: netns (Approach 2 default), proxy (fallback), or auto
        #[arg(long, value_enum, default_value_t = ModeArg::Auto)]
        mode: ModeArg,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Check Linux NetNS, /dev/net/tun, AppArmor, and server connectivity
    Doctor,
    /// Internal git credential helper invoked by git inside `cx exec`
    #[command(hide = true)]
    GitCredential {
        op: Option<String>,
    },
    /// Internal single-threaded Rootless NetNS initializer
    #[command(name = "__netns-init", hide = true)]
    NetnsInit {
        #[arg(long)]
        sock_fd: RawFd,
        #[arg(long)]
        resolv: PathBuf,
        #[arg(long)]
        nsswitch: PathBuf,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Internal single-threaded Rootless NetNS capability probe
    #[command(name = "__netns-probe", hide = true)]
    NetnsProbe,
}

#[derive(Subcommand)]
enum ProfileAction {
    List,
}

#[derive(Subcommand)]
enum KeyAction {
    Create {
        #[arg(short, long)]
        profile: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long, value_delimiter = ',')]
        profiles: Vec<String>,
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
}

fn main() {
    // CRITICAL: Run `__netns-init` strictly single-threaded BEFORE constructing Tokio runtime!
    let cli = Cli::parse();
    if let Commands::NetnsInit {
        sock_fd,
        resolv,
        nsswitch,
        cmd,
    } = cli.command
    {
        if let Err(e) = run_netns_init(sock_fd, &resolv, &nsswitch, &cmd) {
            eprintln!("cx __netns-init error: {e:#}");
            std::process::exit(126);
        }
        return;
    }

    if matches!(cli.command, Commands::NetnsProbe) {
        if let Err(e) = run_netns_probe() {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
        return;
    }

    if let Commands::GitCredential { op } = cli.command {
        cmd_git_credential(op.as_deref());
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    let res = rt.block_on(async move {
        match cli.command {
            Commands::Login {
                server,
                token,
                quic_ca,
                default_profile,
            } => {
                cmd_login(server, token, quic_ca, default_profile).await?;
                Ok::<i32, anyhow::Error>(0)
            }
            Commands::Whoami => {
                cmd_whoami().await?;
                Ok(0)
            }
            Commands::Profile {
                action: ProfileAction::List,
            } => {
                cmd_profile_list().await?;
                Ok(0)
            }
            Commands::Key {
                action: KeyAction::Create { profile, ttl_secs },
            } => {
                cmd_key_create(profile, ttl_secs).await?;
                Ok(0)
            }
            Commands::Token {
                action:
                    TokenAction::Create {
                        name,
                        profiles,
                        ttl_secs,
                    },
            } => {
                cmd_token_create(name, profiles, ttl_secs).await?;
                Ok(0)
            }
            Commands::Exec { profile, mode, cmd } => cmd_exec(profile, mode.into(), cmd).await,
            Commands::Doctor => {
                cmd_doctor().await?;
                Ok(0)
            }
            Commands::GitCredential { .. }
            | Commands::NetnsInit { .. }
            | Commands::NetnsProbe => unreachable!(),
        }
    });

    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("cx error: {e:#}");
            std::process::exit(1);
        }
    }
}
