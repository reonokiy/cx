use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cx_crypto::{EphemeralCa, generate_random_token};
use cx_plugin::{HostPatternValidator, ProviderRegistry};
use cx_server::config::ServerFileConfig;
use cx_server::start_server_with_options;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "cx-server",
    version,
    about = "cx secretless credential-injecting gateway server"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP control plane and QUIC data plane
    Serve {
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
        /// Seed a sample multi-platform `dev` profile (`github` + `openai`) when the database has no profiles
        #[arg(long, default_value_t = false)]
        seed_dev: bool,
    },
    /// Generate a ready-to-run dev layout (`server.toml`, `providers/`)
    Init {
        #[arg(short, long, default_value = ".cx-dev")]
        dir: PathBuf,
    },
    /// List and validate provider manifests
    #[command(alias = "plugin")]
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },
    /// Probe the HTTP control-plane `/healthz` endpoint (used by container HEALTHCHECK)
    Healthcheck {
        #[arg(long, default_value = "http://127.0.0.1:8080/healthz")]
        url: String,
        #[arg(long, default_value_t = 3)]
        timeout_secs: u64,
    },
}

#[derive(Subcommand)]
enum ProviderAction {
    /// List built-in and directory provider plugins
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Validate a provider TOML manifest (including `[virtual_key]` and PSL host guardrails)
    Validate {
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Serve { config, seed_dev } => {
            let cfg = ServerFileConfig::load_from_path(&config)?;
            let running = start_server_with_options(cfg, seed_dev).await?;
            println!(
                "cx-server ready: HTTP control plane on {}, QUIC data plane on {}",
                running.http_addr, running.quic_addr
            );
            wait_for_shutdown_signal().await?;
            println!("shutting down cx-server");
        }
        Commands::Init { dir } => {
            fs::create_dir_all(dir.join("providers"))?;
            let (cert_pem, key_pem) =
                EphemeralCa::generate_dev_server_cert(&["localhost", "127.0.0.1"])?;
            let cert_path = dir.join("quic-cert.pem");
            let key_path = dir.join("quic-key.pem");
            fs::write(&cert_path, cert_pem)?;
            fs::write(&key_path, key_pem)?;

            let dev_token = generate_random_token("cx_dev_", 32);
            let server_cfg_path = dir.join("server.toml");

            let server_toml = format!(
                r#"[http]
listen = "127.0.0.1:8080"
external_url = "http://127.0.0.1:8080"
trusted_proxies = ["127.0.0.1/32", "::1/128"]

[quic]
listen = "127.0.0.1:8443"
public_addr = "127.0.0.1:8443"
server_name = "localhost"
cert = "./quic-cert.pem"
key = "./quic-key.pem"

[postgres]
host = "127.0.0.1"
port = 5432
database = "cx"
username = "cx"
password_env = "CX_POSTGRES_PASSWORD"
ssl_mode = "prefer"
max_connections = 16

[dirs]
providers = "./providers"

[[bootstrap_users]]
email = "dev@localhost"
display_name = "Local Dev"
groups = ["cx-admins", "eng-all"]
token = "{dev_token}"
"#
            );

            fs::write(&server_cfg_path, server_toml)?;

            println!("Initialized dev cx-server layout in {}", dir.display());
            println!("  Server:    {}", server_cfg_path.display());
            println!("  Providers: {}/providers (drop custom *.toml here)", dir.display());
            println!("  QUIC cert: {}", cert_path.display());
            println!("  Dev token: {dev_token}");
            println!("\nNext steps:");
            println!("  docker run -d --name cx-pg -e POSTGRES_USER=cx -e POSTGRES_PASSWORD=cxpass -e POSTGRES_DB=cx -p 127.0.0.1:5432:5432 postgres:17-alpine");
            println!(
                "  CX_POSTGRES_PASSWORD=cxpass CX_MASTER_KEY=$(openssl rand -base64 32) cx-server serve -c {}",
                server_cfg_path.display()
            );
            println!("  Open http://127.0.0.1:8080/ui/ to create your first multi-platform Profile.");
        }
        Commands::Provider { action } => match action {
            ProviderAction::List { dir } => {
                let reg = ProviderRegistry::new(dir, true, HostPatternValidator::default())?;
                for (id, ver, desc) in reg.list_providers() {
                    println!("{id:<16} v{ver:<8} {desc}");
                }
            }
            ProviderAction::Validate { path } => {
                let m = ProviderRegistry::validate_manifest_file(
                    &path,
                    &HostPatternValidator::default(),
                )?;
                let host_count: usize = m.inject.iter().map(|i| i.hosts.len()).sum();
                println!(
                    "OK: provider '{}' v{} (vk={:?}:'{}'+{}, {} inject hosts, {} passthrough hosts, {} injectors)",
                    m.id,
                    m.version,
                    m.virtual_key.format,
                    m.virtual_key.prefix,
                    m.virtual_key.length,
                    host_count,
                    m.passthrough.hosts.len(),
                    m.inject.len()
                );
            }
        },
        Commands::Healthcheck { url, timeout_secs } => {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()?;
            let resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("healthcheck failed: HTTP {} from {}", resp.status(), url);
            }
        }
    }
    Ok(())
}

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => { res?; }
            _ = sigterm.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
