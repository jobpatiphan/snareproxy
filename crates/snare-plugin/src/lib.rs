//! WASM plugin host (design: docs/design/wasm-plugins.md, phase P1).
//!
//! Loads `.wasm` **components** (see `wit/world.wit`) and runs their
//! `on-request` / `on-response` hooks with a fuel budget per call. The host
//! exposes a single capability so far — `log`. Guest instances are created
//! per-call (stateless), so the host is `Send + Sync` and can be shared behind
//! an `Arc` and called from the async engine directly (like the SQLite store,
//! blocking is acceptable).

use std::path::Path;

use anyhow::{Context, Result};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

mod bindings {
    wasmtime::component::bindgen!({
        world: "plugin",
        path: "wit",
    });
}
use bindings::exports::snare::plugin::hooks;
use bindings::snare::plugin::host::Host as HostCap;
use bindings::Plugin;

/// Fuel budget per hook call (instructions). Enough for normal logic, bounded so
/// a runaway plugin can't hang the proxy.
const FUEL_PER_CALL: u64 = 200_000_000;

/// A request/response as handed to plugins (decoupled from the engine model).
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A plugin's decision for a request/response.
#[derive(Debug)]
pub enum Decision<T> {
    Unchanged,
    Forward(T),
    Drop,
}

struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    plugin: String,
}

impl WasiView for State {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

// The `types` interface has no functions — just an empty marker trait to satisfy.
impl bindings::snare::plugin::types::Host for State {}

impl HostCap for State {
    fn log(&mut self, level: String, msg: String) {
        match level.as_str() {
            "error" => tracing::error!(target: "snare_plugin", "[{}] {msg}", self.plugin),
            "warn" => tracing::warn!(target: "snare_plugin", "[{}] {msg}", self.plugin),
            _ => tracing::info!(target: "snare_plugin", "[{}] {msg}", self.plugin),
        }
    }
}

struct Loaded {
    name: String,
    component: Component,
}

/// Shared plugin host. Cheap to `Arc`-clone.
pub struct PluginHost {
    engine: Engine,
    linker: Linker<State>,
    plugins: Vec<Loaded>,
}

impl PluginHost {
    /// Load every `*.wasm` component in `dir` (missing dir = no plugins).
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        let engine = Engine::new(&config).context("wasmtime engine")?;

        let mut linker: Linker<State> = Linker::new(&engine);
        wasmtime_wasi::add_to_linker_sync(&mut linker).context("link wasi")?;
        Plugin::add_to_linker(&mut linker, |s: &mut State| s).context("link host caps")?;

        let mut plugins = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                    continue;
                }
                match Self::load_one(&engine, &linker, &path) {
                    Ok(loaded) => {
                        tracing::info!("loaded plugin '{}' from {}", loaded.name, path.display());
                        plugins.push(loaded);
                    }
                    Err(e) => tracing::warn!("skipping plugin {}: {e:#}", path.display()),
                }
            }
        }
        Ok(Self {
            engine,
            linker,
            plugins,
        })
    }

    fn load_one(engine: &Engine, linker: &Linker<State>, path: &Path) -> Result<Loaded> {
        let component = Component::from_file(engine, path).context("load component")?;
        // Instantiate once to read the reported name and validate the ABI.
        let mut store = new_store(engine, "loader");
        let instance = linker
            .instantiate(&mut store, &component)
            .context("instantiate")?;
        let plugin = Plugin::new(&mut store, &instance)?;
        let name = plugin
            .snare_plugin_hooks()
            .call_name(&mut store)
            .unwrap_or_else(|_| "unnamed".into());
        Ok(Loaded { name, component })
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name.clone()).collect()
    }

    /// Run every plugin's `on-request` in order. The first Drop wins; edits chain.
    pub fn on_request(&self, req: Req) -> Decision<Req> {
        let mut current = req;
        let mut changed = false;
        for p in &self.plugins {
            match self.call_request(p, &current) {
                Ok(hooks::ReqAction::Drop) => return Decision::Drop,
                Ok(hooks::ReqAction::Forward(w)) => {
                    current = from_wit_req(w);
                    changed = true;
                }
                Ok(hooks::ReqAction::Unchanged) => {}
                Err(e) => tracing::warn!("plugin '{}' on-request failed: {e:#}", p.name),
            }
        }
        if changed {
            Decision::Forward(current)
        } else {
            Decision::Unchanged
        }
    }

    /// Run every plugin's `on-response` in order.
    pub fn on_response(&self, resp: Resp) -> Decision<Resp> {
        let mut current = resp;
        let mut changed = false;
        for p in &self.plugins {
            match self.call_response(p, &current) {
                Ok(hooks::RespAction::Drop) => return Decision::Drop,
                Ok(hooks::RespAction::Forward(w)) => {
                    current = from_wit_resp(w);
                    changed = true;
                }
                Ok(hooks::RespAction::Unchanged) => {}
                Err(e) => tracing::warn!("plugin '{}' on-response failed: {e:#}", p.name),
            }
        }
        if changed {
            Decision::Forward(current)
        } else {
            Decision::Unchanged
        }
    }

    fn call_request(&self, p: &Loaded, req: &Req) -> Result<hooks::ReqAction> {
        let mut store = new_store(&self.engine, &p.name);
        let instance = self.linker.instantiate(&mut store, &p.component)?;
        let plugin = Plugin::new(&mut store, &instance)?;
        plugin
            .snare_plugin_hooks()
            .call_on_request(&mut store, &to_wit_req(req))
    }

    fn call_response(&self, p: &Loaded, resp: &Resp) -> Result<hooks::RespAction> {
        let mut store = new_store(&self.engine, &p.name);
        let instance = self.linker.instantiate(&mut store, &p.component)?;
        let plugin = Plugin::new(&mut store, &instance)?;
        plugin
            .snare_plugin_hooks()
            .call_on_response(&mut store, &to_wit_resp(resp))
    }
}

fn new_store(engine: &Engine, plugin: &str) -> Store<State> {
    let mut store = Store::new(
        engine,
        State {
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            plugin: plugin.to_string(),
        },
    );
    let _ = store.set_fuel(FUEL_PER_CALL);
    store
}

fn to_wit_req(r: &Req) -> hooks::HttpRequest {
    hooks::HttpRequest {
        method: r.method.clone(),
        url: r.url.clone(),
        headers: r.headers.clone(),
        body: r.body.clone(),
    }
}
fn from_wit_req(w: hooks::HttpRequest) -> Req {
    Req {
        method: w.method,
        url: w.url,
        headers: w.headers,
        body: w.body,
    }
}
fn to_wit_resp(r: &Resp) -> hooks::HttpResponse {
    hooks::HttpResponse {
        status: r.status,
        headers: r.headers.clone(),
        body: r.body.clone(),
    }
}
fn from_wit_resp(w: hooks::HttpResponse) -> Resp {
    Resp {
        status: w.status,
        headers: w.headers,
        body: w.body,
    }
}
