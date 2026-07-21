//! `bogbogproxd` — the BogBogProx daemon: proxy engine + REST API + project store.

mod active_scan;
mod api;
mod auth;
mod config;
mod intruder;
mod macros;
mod paths;
mod pubsub;
mod repeater;
mod sequencer;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use bogbogprox_core::store::{FlowQuery, FlowStore};
use bogbogprox_engine::{generate_ca, EngineConfig, EngineServices};
use bogbogprox_store_sqlite::SqliteStore;

use crate::paths::Paths;

#[derive(Parser)]
#[command(
    name = "bogbogproxd",
    version,
    about = "BogBogProx daemon — Rust-native web security proxy"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// CA management (§28).
    Ca {
        #[command(subcommand)]
        action: CaCmd,
    },
    /// Run the proxy + REST API.
    Run {
        /// Proxy listen address. (8888 by default — 8080 is a common clash.)
        #[arg(long, default_value = "127.0.0.1:8888")]
        proxy: SocketAddr,
        /// REST API listen address.
        #[arg(long, default_value = "127.0.0.1:9000")]
        api: SocketAddr,
        /// Team mode: use a shared Postgres store instead of local SQLite,
        /// e.g. `postgres://bogbogprox:bogbogprox@host:5432/bogbogprox` (design: team-mode.md T1).
        #[arg(long)]
        postgres: Option<String>,
        /// Team mode: require this shared project token to join (T2). Operators
        /// call `POST /api/v1/team/join` with it to get a session token. Unset =
        /// local mode, no auth.
        #[arg(long)]
        auth_token: Option<String>,
    },
    /// Launch an isolated browser profile with proxying and test-only certificate
    /// error bypass — similar to Burp's embedded browser.
    Browser {
        /// Proxy to route the browser through.
        #[arg(long, default_value = "127.0.0.1:8888")]
        proxy: SocketAddr,
        /// Start URL.
        #[arg(long, default_value = "about:blank")]
        url: String,
    },
    /// List captured flows.
    Flows {
        #[arg(long)]
        search: Option<String>,
        #[arg(long, default_value_t = 40)]
        limit: i64,
    },
    /// Delete every captured flow.
    Flush,
}

#[derive(Subcommand)]
enum CaCmd {
    /// Generate a fresh CA (idempotent unless --force).
    Generate {
        #[arg(long)]
        force: bool,
    },
    /// Print the path to the CA certificate to install.
    Path,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bogbogproxd=info,bogbogprox_engine=info,bogbogprox_plugin=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let paths = Paths::resolve()?;

    match cli.cmd {
        Cmd::Ca { action } => cmd_ca(&paths, action),
        Cmd::Run {
            proxy,
            api,
            postgres,
            auth_token,
        } => {
            let postgres = postgres.or_else(|| std::env::var("BOGBOGPROX_POSTGRES").ok());
            let auth_token = auth_token.or_else(|| std::env::var("BOGBOGPROX_AUTH_TOKEN").ok());
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_run(&paths, proxy, api, postgres, auth_token))
        }
        Cmd::Browser { proxy, url } => cmd_browser(proxy, &url),
        Cmd::Flows { search, limit } => cmd_flows(&paths, search, limit),
        Cmd::Flush => cmd_flush(&paths),
    }
}

fn open_store(paths: &Paths) -> Result<SqliteStore> {
    paths::secure_dir(&paths.data_dir).context("create data dir")?;
    SqliteStore::open(paths.db())
}

fn cmd_ca(paths: &Paths, action: CaCmd) -> Result<()> {
    match action {
        CaCmd::Generate { force } => {
            paths::secure_dir(&paths.config_dir).context("create config dir")?;
            paths::secure_dir(&paths.ca_dir()).context("create ca dir")?;
            if paths.ca_key().exists() && !force {
                println!(
                    "CA already exists at {}\n(use `bogbogproxd ca generate --force` to replace)",
                    paths.ca_cert().display()
                );
                return Ok(());
            }
            let ca = generate_ca()?;
            std::fs::write(paths.ca_cert(), &ca.cert_pem)?;
            std::fs::write(paths.ca_key(), &ca.key_pem)?;
            set_key_perms(&paths.ca_key());
            println!("✔ Generated CA");
            println!("  cert: {}", paths.ca_cert().display());
            println!("  key : {} (keep private)", paths.ca_key().display());
            println!("\nInstall the cert in your browser/OS trust store, then run:");
            println!("  bogbogproxd run");
            Ok(())
        }
        CaCmd::Path => {
            if !paths.ca_cert().exists() {
                bail!("no CA yet — run `bogbogproxd ca generate`");
            }
            println!("{}", paths.ca_cert().display());
            Ok(())
        }
    }
}

#[cfg(unix)]
fn set_key_perms(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_key_perms(_path: &std::path::Path) {}

async fn cmd_run(
    paths: &Paths,
    proxy_addr: SocketAddr,
    api_addr: SocketAddr,
    postgres: Option<String>,
    auth_token: Option<String>,
) -> Result<()> {
    if !paths.ca_key().exists() {
        bail!("no CA yet — run `bogbogproxd ca generate` first");
    }
    let ca_cert_pem = std::fs::read_to_string(paths.ca_cert())?;
    let ca_key_pem = std::fs::read_to_string(paths.ca_key())?;

    paths::secure_dir(&paths.config_dir).context("secure config dir")?;
    paths::secure_dir(&paths.data_dir).context("secure data dir")?;
    let local_config_path = paths.config_file();

    // Team mode: shared Postgres flows + config; otherwise local files.
    let (store_dyn, config_backend): (Arc<dyn FlowStore>, config::Backend) = match &postgres {
        Some(url) => {
            let pg = bogbogprox_store_postgres::PostgresStore::connect(url)
                .context("connect Postgres (team mode)")?;
            tracing::info!("store: Postgres (team mode)");
            (Arc::new(pg.clone()), config::Backend::Postgres(pg))
        }
        None => {
            tracing::info!("store: SQLite (local)");
            (
                Arc::new(open_store(paths)?),
                config::Backend::Local(local_config_path.clone()),
            )
        }
    };
    let (events, _rx) = tokio::sync::broadcast::channel(1024);
    // Cross-process events from other daemons (topology B); merged into SSE.
    let (remote_events, _rrx) = tokio::sync::broadcast::channel(1024);
    let intercept = Arc::new(bogbogprox_core::intercept::Intercept::new());
    let rules = Arc::new(bogbogprox_core::rules::Rules::new());
    let scanner = Arc::new(bogbogprox_core::scanner::Scanner::new());
    let wslog = Arc::new(bogbogprox_core::ws::WsLog::new());
    let vars = Arc::new(bogbogprox_core::session::Vars::new());
    let session_macros = Arc::new(bogbogprox_core::session::Macros::new());
    let annotations = Arc::new(bogbogprox_core::annotate::Annotations::new());

    // Restore persisted state (rules / scope / scanner / vars / macros / notes).
    if let Some(persisted) = config_backend.load() {
        config::apply(
            &persisted,
            &rules,
            &intercept,
            &scanner,
            &vars,
            &session_macros,
            &annotations,
        );
        tracing::info!("restored {} persisted rule(s)", persisted.rules.len());
    }

    // Relay events across daemons and apply shared state locally when another
    // operator mutates it.
    if let Some(url) = &postgres {
        pubsub::start(url.clone(), events.clone(), remote_events.clone());
        let mut remote_rx = remote_events.subscribe();
        let shared_config = config_backend.clone();
        let shared_rules = rules.clone();
        let shared_intercept = intercept.clone();
        let shared_scanner = scanner.clone();
        let shared_vars = vars.clone();
        let shared_macros = session_macros.clone();
        let shared_annotations = annotations.clone();
        let shared_wslog = wslog.clone();
        tokio::spawn(async move {
            while let Ok(event) = remote_rx.recv().await {
                match event {
                    bogbogprox_core::model::FlowEvent::ConfigChanged { .. } => {
                        if let Some(persisted) = shared_config.load() {
                            config::apply(
                                &persisted,
                                &shared_rules,
                                &shared_intercept,
                                &shared_scanner,
                                &shared_vars,
                                &shared_macros,
                                &shared_annotations,
                            );
                        }
                    }
                    bogbogprox_core::model::FlowEvent::Finding { finding } => {
                        shared_scanner.ingest(finding);
                    }
                    bogbogprox_core::model::FlowEvent::WsMessage { msg } => {
                        shared_wslog.ingest(msg);
                    }
                    _ => {}
                }
            }
        });
        tracing::info!("cross-process events/config: Postgres LISTEN/NOTIFY");
    }

    let auth_enabled = auth_token.is_some();

    // REST API — shares the live event bus, the intercept breakpoint, the
    // match/replace rules, and the passive scanner with the proxy engine.
    let app = api::router(api::AppState {
        store: store_dyn.clone(),
        events: events.clone(),
        intercept: intercept.clone(),
        rules: rules.clone(),
        scanner: scanner.clone(),
        wslog: wslog.clone(),
        vars: vars.clone(),
        macros: session_macros.clone(),
        annotations: annotations.clone(),
        auth: Arc::new(auth::Auth::new(auth_token)),
        remote_events: remote_events.clone(),
        config: config_backend,
        proxy_addr,
    });
    let listener = tokio::net::TcpListener::bind(api_addr)
        .await
        .with_context(|| format!("bind API {api_addr}"))?;
    tracing::info!("REST API on http://{api_addr}");
    let api_task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        {
            tracing::error!(%error, "REST API stopped unexpectedly");
        }
    });

    // Proxy engine
    let cfg = EngineConfig {
        listen: proxy_addr,
        ca_cert_pem,
        ca_key_pem,
    };
    println!("BogBogProx running.");
    println!("  proxy     : http://{proxy_addr}  (point your browser/agent here)");
    println!("  api       : http://{api_addr}");
    println!("  dashboard : http://{api_addr}/  ← open this to watch traffic live");
    if auth_enabled {
        println!("  auth      : TEAM MODE — operators must join with the project token");
        println!("              (serve behind TLS / a reverse proxy before exposing it)");
    }
    println!("  press Ctrl-C to stop");

    // WASM plugins from <config_dir>/plugins (missing dir = none).
    let plugins = Arc::new(
        bogbogprox_plugin::PluginHost::load_dir(&paths.config_dir.join("plugins"))
            .context("init plugin host")?,
    );
    if !plugins.is_empty() {
        println!("  plugins   : {}", plugins.names().join(", "));
    }

    let services = EngineServices {
        store: store_dyn,
        events,
        intercept,
        rules,
        scanner,
        vars,
        wslog,
        plugins,
    };
    bogbogprox_engine::run(cfg, services, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    api_task.abort();
    Ok(())
}

#[cfg(target_os = "windows")]
const BROWSER_CANDIDATES: &[&str] = &["chrome.exe", "msedge.exe", "brave.exe", "chromium.exe"];
#[cfg(not(target_os = "windows"))]
const BROWSER_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
];

/// Create a fresh throwaway browser profile directory (0700).
fn make_browser_profile() -> Result<std::path::PathBuf> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|e| anyhow::anyhow!("create private browser profile name: {e}"))?;
    let suffix = u64::from_le_bytes(random);
    let profile = std::env::temp_dir().join(format!(
        "bogbogprox-browser-{}-{suffix:016x}",
        std::process::id()
    ));
    paths::secure_dir(&profile).context("create throwaway browser profile")?;
    Ok(profile)
}

/// Chromium flags that wire the browser to the proxy, accept the MITM cert, and
/// silence Chromium's phone-home traffic so the only flows captured are the ones
/// *you* generate — not component updates, Safe Browsing, sync, or NTP pings.
fn browser_flags(proxy: SocketAddr, profile: &std::path::Path, url: &str) -> Vec<String> {
    vec![
        format!("--proxy-server=http://{proxy}"),
        "--proxy-bypass-list=<-loopback>".into(),
        "--ignore-certificate-errors".into(),
        "--disable-background-mode".into(),
        format!("--user-data-dir={}", profile.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-sync".into(),
        "--disable-domain-reliability".into(),
        "--disable-client-side-phishing-detection".into(),
        "--disable-breakpad".into(),
        "--disable-default-apps".into(),
        "--no-pings".into(),
        "--metrics-recording-only".into(),
        "--disable-features=OptimizationHints,Translate,MediaRouter,InterestFeedContentSuggestions,ChromeWhatsNewUI".into(),
        url.to_string(),
    ]
}

/// Spawn the throwaway browser fire-and-forget and reap its temp profile when it
/// exits. Returns the browser binary that launched. Used by the dashboard's
/// "Open browser" button so the operator never touches the CLI.
pub(crate) fn launch_browser_detached(proxy: SocketAddr, url: &str) -> Result<String> {
    let profile = make_browser_profile()?;
    let flags = browser_flags(proxy, &profile, url);
    let mut failures = Vec::new();
    for browser in BROWSER_CANDIDATES {
        match std::process::Command::new(browser).args(&flags).spawn() {
            Ok(mut child) => {
                let prof = profile.clone();
                std::thread::spawn(move || {
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&prof);
                });
                return Ok((*browser).to_string());
            }
            Err(e) => failures.push(format!("{browser}: {e}")),
        }
    }
    let _ = std::fs::remove_dir_all(&profile);
    bail!(
        "no Chromium-family browser could be launched (tried {}). Details: {}",
        BROWSER_CANDIDATES.join(", "),
        failures.join("; ")
    )
}

/// Launch a Chromium-family browser pre-wired to the proxy, in a throwaway
/// profile — the CLI "embedded browser". Blocks until the browser closes, then
/// removes the profile.
fn cmd_browser(proxy: SocketAddr, url: &str) -> Result<()> {
    let profile = make_browser_profile()?;
    struct ProfileGuard(std::path::PathBuf);
    impl Drop for ProfileGuard {
        fn drop(&mut self) {
            if let Err(e) = std::fs::remove_dir_all(&self.0) {
                eprintln!(
                    "warning: could not remove browser profile {}: {e}",
                    self.0.display()
                );
            }
        }
    }
    let _profile_guard = ProfileGuard(profile.clone());
    let flags = browser_flags(proxy, &profile, url);

    let mut failures = Vec::new();
    for browser in BROWSER_CANDIDATES {
        match std::process::Command::new(browser).args(&flags).spawn() {
            Ok(mut child) => {
                println!("Launching {browser} → proxy {proxy}");
                println!("  temporary profile: {}", profile.display());
                println!("  close the browser to return and remove the temporary profile");
                let status = child
                    .wait()
                    .with_context(|| format!("wait for {browser}"))?;
                if !status.success() {
                    bail!("{browser} exited with {status}");
                }
                return Ok(());
            }
            Err(e) => failures.push(format!("{browser}: {e}")),
        }
    }
    bail!(
        "no Chromium-family browser could be launched (tried {}). Details: {}",
        BROWSER_CANDIDATES.join(", "),
        failures.join("; ")
    )
}

fn cmd_flows(paths: &Paths, search: Option<String>, limit: i64) -> Result<()> {
    let store = open_store(paths)?;
    let q = FlowQuery {
        search,
        host: None,
        limit,
        offset: 0,
    };
    let flows = store.list_flows(&q)?;
    if flows.is_empty() {
        println!("(no flows captured yet)");
        return Ok(());
    }
    for f in flows {
        let status = f
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "…".into());
        println!(
            "#{:<5} {:>3} {:<6} {}://{}{}",
            f.id, status, f.method, f.scheme, f.host, f.path
        );
    }
    Ok(())
}

fn cmd_flush(paths: &Paths) -> Result<()> {
    let store = open_store(paths)?;
    let n = store.count()?;
    store.clear()?;
    println!("✔ cleared {n} flows");
    Ok(())
}
