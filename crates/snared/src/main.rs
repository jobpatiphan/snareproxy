//! `snared` — the Snare daemon: proxy engine + REST API + project store.

mod active_scan;
mod api;
mod config;
mod intruder;
mod paths;
mod repeater;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use snare_core::store::{FlowQuery, FlowStore};
use snare_engine::{generate_ca, EngineConfig};
use snare_store_sqlite::SqliteStore;

use crate::paths::Paths;

#[derive(Parser)]
#[command(name = "snared", version, about = "Snare daemon — Rust-native web security proxy")]
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
                .unwrap_or_else(|_| "snared=info,snare_engine=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let paths = Paths::resolve()?;

    match cli.cmd {
        Cmd::Ca { action } => cmd_ca(&paths, action),
        Cmd::Run { proxy, api } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(cmd_run(&paths, proxy, api))
        }
        Cmd::Flows { search, limit } => cmd_flows(&paths, search, limit),
        Cmd::Flush => cmd_flush(&paths),
    }
}

fn open_store(paths: &Paths) -> Result<SqliteStore> {
    std::fs::create_dir_all(&paths.data_dir).context("create data dir")?;
    SqliteStore::open(paths.db())
}

fn cmd_ca(paths: &Paths, action: CaCmd) -> Result<()> {
    match action {
        CaCmd::Generate { force } => {
            std::fs::create_dir_all(paths.ca_dir()).context("create ca dir")?;
            if paths.ca_key().exists() && !force {
                println!(
                    "CA already exists at {}\n(use `snared ca generate --force` to replace)",
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
            println!("  snared run");
            Ok(())
        }
        CaCmd::Path => {
            if !paths.ca_cert().exists() {
                bail!("no CA yet — run `snared ca generate`");
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

async fn cmd_run(paths: &Paths, proxy_addr: SocketAddr, api_addr: SocketAddr) -> Result<()> {
    if !paths.ca_key().exists() {
        bail!("no CA yet — run `snared ca generate` first");
    }
    let ca_cert_pem = std::fs::read_to_string(paths.ca_cert())?;
    let ca_key_pem = std::fs::read_to_string(paths.ca_key())?;

    let store = Arc::new(open_store(paths)?);
    let store_dyn: Arc<dyn FlowStore> = store.clone();
    let (events, _rx) = tokio::sync::broadcast::channel(1024);
    let intercept = Arc::new(snare_core::intercept::Intercept::new());
    let rules = Arc::new(snare_core::rules::Rules::new());
    let scanner = Arc::new(snare_core::scanner::Scanner::new());
    let wslog = Arc::new(snare_core::ws::WsLog::new());

    // Restore persisted rules / scope / scanner state from the last run.
    let config_path = paths.config_file();
    if let Some(persisted) = config::load(&config_path) {
        config::apply(&persisted, &rules, &intercept, &scanner);
        tracing::info!("restored {} rule(s) from {}", persisted.rules.len(), config_path.display());
    }

    // REST API — shares the live event bus, the intercept breakpoint, the
    // match/replace rules, and the passive scanner with the proxy engine.
    let app = api::router(api::AppState {
        store: store_dyn.clone(),
        events: events.clone(),
        intercept: intercept.clone(),
        rules: rules.clone(),
        scanner: scanner.clone(),
        wslog: wslog.clone(),
        config_path: config_path.clone(),
    });
    let listener = tokio::net::TcpListener::bind(api_addr)
        .await
        .with_context(|| format!("bind API {api_addr}"))?;
    tracing::info!("REST API on http://{api_addr}");
    let api_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
    });

    // Proxy engine
    let cfg = EngineConfig {
        listen: proxy_addr,
        ca_cert_pem,
        ca_key_pem,
    };
    println!("Snare running.");
    println!("  proxy     : http://{proxy_addr}  (point your browser/agent here)");
    println!("  api       : http://{api_addr}");
    println!("  dashboard : http://{api_addr}/  ← open this to watch traffic live");
    println!("  press Ctrl-C to stop");

    snare_engine::run(cfg, store_dyn, events, intercept, rules, scanner, wslog, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    api_task.abort();
    Ok(())
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
        let status = f.status.map(|s| s.to_string()).unwrap_or_else(|| "…".into());
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
