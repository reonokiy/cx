use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use cx_protocol::{
    CliLoginPollRequest, CliLoginPollResponse, CliLoginStartResponse, CreateScopedTokenRequest,
    CreateScopedTokenResponse, CreateSessionRequest, CreateSessionResponse,
    CreateVirtualKeyRequest, CreateVirtualKeyResponse, ProfileSummary, UserSummary,
};
use serde::{Deserialize, Serialize};

use crate::netns::diagnose_netns;
use crate::runner::{InterceptMode, execute_command};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCredentials {
    pub server_url: String,
    pub access_token: String,
    #[serde(default)]
    pub quic_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub default_profile: Option<String>,
}

impl ClientCredentials {
    pub fn default_path() -> anyhow::Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("could not locate user config directory")?
            .join("cx");
        Ok(dir.join("credentials.json"))
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::default_path()?;
        let raw = fs::read_to_string(&path).with_context(|| {
            format!(
                "not logged in (missing {}); run `cx login --server <url>` first",
                path.display()
            )
        })?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save(&self) -> anyhow::Result<PathBuf> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }
}

pub async fn cmd_login(
    server: String,
    token: Option<String>,
    quic_ca: Option<PathBuf>,
    default_profile: Option<String>,
) -> anyhow::Result<()> {
    let server_url = server.trim_end_matches('/').to_string();
    let http = reqwest::Client::new();

    let access_token = if let Some(tok) = token {
        // Validate supplied PAT/bootstrap token against /v1/whoami
        let resp = http
            .get(format!("{server_url}/v1/whoami"))
            .bearer_auth(&tok)
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!(
                "token authentication failed ({}): {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let user: UserSummary = resp.json().await?;
        println!(
            "Authenticated as {} ({}) [groups: {}]",
            user.email,
            user.display_name,
            user.groups.join(", ")
        );
        tok
    } else {
        // Server-relayed OIDC login (works on headless Linux SSH and desktop!)
        let start_resp = http
            .post(format!("{server_url}/v1/auth/cli/start"))
            .send()
            .await?;
        if !start_resp.status().is_success() {
            bail!(
                "OIDC login start failed ({}): {}",
                start_resp.status(),
                start_resp.text().await.unwrap_or_default()
            );
        }
        let start: CliLoginStartResponse = start_resp.json().await?;
        println!("Open this URL in any browser to sign in:");
        println!("  {}", start.verification_url);
        println!("  Verification code: {}", start.user_code);
        println!("Waiting for approval...");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(start.expires_in_secs);
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("login timed out");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            let poll: CliLoginPollResponse = http
                .post(format!("{server_url}/v1/auth/cli/poll"))
                .json(&CliLoginPollRequest {
                    login_id: start.login_id.clone(),
                    poll_secret: start.poll_secret.clone(),
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            match poll.status.as_str() {
                "approved" => {
                    let tok = poll
                        .access_token
                        .context("server approved login without access_token")?;
                    if let Some(user) = poll.user {
                        println!(
                            "Signed in as {} ({}) [groups: {}]",
                            user.email,
                            user.display_name,
                            user.groups.join(", ")
                        );
                    }
                    break tok;
                }
                "expired" => bail!("login code expired"),
                _ => continue,
            }
        }
    };

    let creds = ClientCredentials {
        server_url,
        access_token,
        quic_ca_path: quic_ca.map(|p| fs::canonicalize(&p).unwrap_or(p)),
        default_profile,
    };
    let saved = creds.save()?;
    println!("Credentials saved to {} (mode 0600)", saved.display());
    Ok(())
}

pub async fn cmd_whoami() -> anyhow::Result<()> {
    let creds = ClientCredentials::load()?;
    let http = reqwest::Client::new();
    let user: UserSummary = http
        .get(format!("{}/v1/whoami", creds.server_url))
        .bearer_auth(&creds.access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("Server: {}", creds.server_url);
    println!("User:   {} ({})", user.email, user.display_name);
    println!("ID:     {}", user.id);
    println!("Groups: {}", user.groups.join(", "));
    Ok(())
}

pub async fn cmd_profile_list() -> anyhow::Result<()> {
    let creds = ClientCredentials::load()?;
    let http = reqwest::Client::new();
    let profiles: Vec<ProfileSummary> = http
        .get(format!("{}/v1/profiles", creds.server_url))
        .bearer_auth(&creds.access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if profiles.is_empty() {
        println!("No profiles available for your account.");
        return Ok(());
    }
    for p in profiles {
        let plats: Vec<&str> = p.platforms.iter().map(|pl| pl.id.as_str()).collect();
        println!(
            "{:<18} platforms={:?} inject={:?} server_tunnel={:?}",
            p.name, plats, p.inject_hosts, p.server_tunnel_hosts
        );
    }
    Ok(())
}

pub async fn cmd_key_create(
    profile: String,
    platform: Option<String>,
    ttl_secs: Option<u64>,
) -> anyhow::Result<()> {
    let creds = ClientCredentials::load()?;
    let http = reqwest::Client::new();
    let resp: CreateVirtualKeyResponse = http
        .post(format!("{}/v1/virtual-keys", creds.server_url))
        .bearer_auth(&creds.access_token)
        .json(&CreateVirtualKeyRequest {
            profile,
            platform,
            ttl_secs,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!(
        "Virtual key created (profile: {}, platform: {}):",
        resp.profile, resp.platform
    );
    println!("  {}", resp.virtual_key);
    println!("Note: this key is a harmless placeholder; it only works when executed via `cx exec`.");
    Ok(())
}

pub async fn cmd_token_create(
    name: String,
    profiles: Vec<String>,
    ttl_secs: Option<u64>,
) -> anyhow::Result<()> {
    let creds = ClientCredentials::load()?;
    let http = reqwest::Client::new();
    let resp: CreateScopedTokenResponse = http
        .post(format!("{}/v1/tokens", creds.server_url))
        .bearer_auth(&creds.access_token)
        .json(&CreateScopedTokenRequest {
            name,
            profiles,
            ttl_secs,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("Scoped access token created (id: {}):", resp.id);
    println!("  {}", resp.token);
    Ok(())
}

pub async fn cmd_exec(
    profile_opt: Option<String>,
    mode: InterceptMode,
    cmd: Vec<String>,
) -> anyhow::Result<i32> {
    let creds = ClientCredentials::load()?;
    let profile = profile_opt
        .or(creds.default_profile.clone())
        .context("missing --profile <name> (or set default_profile during `cx login`)")?;

    let http = reqwest::Client::new();
    let resp = http
        .post(format!("{}/v1/sessions", creds.server_url))
        .bearer_auth(&creds.access_token)
        .json(&CreateSessionRequest { profile })
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!(
            "failed to create cx session ({}): {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let session: CreateSessionResponse = resp.json().await?;

    let quic_ca_pem = creds
        .quic_ca_path
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .context("failed to read configured --quic-ca file")?;

    let code = execute_command(&session, quic_ca_pem, mode, &cmd).await?;

    // Best-effort immediate session revocation on exit
    let _ = http
        .delete(format!(
            "{}/v1/sessions/{}",
            creds.server_url, session.session_id
        ))
        .bearer_auth(&creds.access_token)
        .send()
        .await;

    Ok(code)
}

pub fn cmd_git_credential(op: Option<&str>) {
    if op != Some("get") {
        return;
    }
    // Parse `host=...` from git credential stdin
    let mut requested_host = String::new();
    let mut input = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_ok() {
        for line in input.lines() {
            if let Some(h) = line.strip_prefix("host=") {
                requested_host = h.trim().to_ascii_lowercase();
                break;
            }
        }
    }
    if let Ok(raw_map) = std::env::var("CX_GIT_CRED_MAP") {
        if let Ok(map) = serde_json::from_str::<std::collections::BTreeMap<String, serde_json::Value>>(&raw_map) {
            let entry = if !requested_host.is_empty() {
                map.get(&requested_host)
            } else if map.len() == 1 {
                map.values().next()
            } else {
                None
            };
            if let Some(entry) = entry {
                if let (Some(user), Some(vkey)) = (
                    entry.get("user").and_then(|v| v.as_str()),
                    entry.get("vkey").and_then(|v| v.as_str()),
                ) {
                    println!("username={user}");
                    println!("password={vkey}");
                    return;
                }
            }
        }
    }
    if let (Ok(user), Ok(vkey)) = (
        std::env::var("CX_GIT_CRED_USER"),
        std::env::var("CX_GIT_CRED_VKEY"),
    ) {
        println!("username={user}");
        println!("password={vkey}");
    }
}

pub async fn cmd_doctor() -> anyhow::Result<()> {
    println!("=== cx doctor (Linux) ===");
    let diag = diagnose_netns();
    println!(
        "  /dev/net/tun readable/writable: {}",
        if diag.tun_accessible { "OK" } else { "FAILED" }
    );
    println!(
        "  Unprivileged User+Net NS:       {} ({})",
        if diag.unshare_works { "OK" } else { "BLOCKED" },
        diag.details
    );

    if !diag.unshare_works && diag.apparmor_restrict_userns {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/usr/local/bin/cx".into());
        println!("\n  [Hint] Ubuntu AppArmor restricts unprivileged userns (`apparmor_restrict_unprivileged_userns=1`).");
        println!("  To permanently enable Rootless NetNS transparent mode for `cx`, install /etc/apparmor.d/cx:");
        println!("    abi <abi/4.0>,");
        println!("    include <tunables/global>");
        println!("    profile cx {exe} flags=(unconfined) {{");
        println!("      userns,");
        println!("      @{{exec_path}} mrix,");
        println!("    }}");
        println!("  Then run: sudo apparmor_parser -r /etc/apparmor.d/cx");
        println!("  Or run with `--mode proxy` in restricted environments.");
    }

    match ClientCredentials::load() {
        Ok(creds) => {
            println!("\n  Configured server: {}", creds.server_url);
            let http = reqwest::Client::new();
            match http
                .get(format!("{}/healthz", creds.server_url))
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => println!("  Control plane HTTPS: OK"),
                Ok(r) => println!("  Control plane HTTPS: HTTP {}", r.status()),
                Err(e) => println!("  Control plane HTTPS: FAILED ({e})"),
            }
        }
        Err(_) => {
            println!("\n  Not logged in yet (`cx login --server <url>`).");
        }
    }
    Ok(())
}
