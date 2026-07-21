//! Loads the built `header-tagger` example component and checks its hooks.
//! Skips if the example hasn't been built (needs the wasm32-wasip2 target):
//!   (cd examples/plugins/header-tagger && cargo build --release --target wasm32-wasip2)

use std::path::Path;

use bogbogprox_plugin::{Decision, PluginHost, Req};

fn example_dir() -> String {
    format!(
        "{}/../../examples/plugins/header-tagger/target/wasm32-wasip2/release",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn plugin_loads_and_tags_request() {
    let dir = example_dir();
    if !Path::new(&format!("{dir}/header_tagger.wasm")).exists() {
        eprintln!("example plugin not built — skipping");
        return;
    }

    let host = PluginHost::load_dir(Path::new(&dir)).expect("load plugins");
    assert_eq!(host.names(), vec!["header-tagger".to_string()]);

    let req = Req {
        method: "GET".into(),
        url: "https://example.com/".into(),
        headers: vec![("Host".into(), "example.com".into())],
        body: vec![],
    };
    match host.on_request(req) {
        Decision::Forward(r) => {
            assert!(
                r.headers
                    .iter()
                    .any(|(k, v)| k == "X-BogBogProx-Plugin" && v == "header-tagger"),
                "plugin should have tagged the request; headers = {:?}",
                r.headers
            );
        }
        other => panic!("expected Forward, got {other:?}"),
    }
}
