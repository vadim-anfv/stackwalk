// debug builds serve web/ from disk; the embedded page is for release (and the tests)
#[cfg_attr(debug_assertions, allow(dead_code))]
mod assets;
mod api;
#[cfg(test)]
mod core_vectors;
mod keys;
mod metrics;
mod model;
mod paths;
mod real_keys;
mod sat;
mod scenario;
mod script_parse;
mod scriptexec;
mod spend;
mod trace;
mod tree;

#[cfg(debug_assertions)]
use std::path::Path;

#[cfg(debug_assertions)]
use axum::Router;
#[cfg(debug_assertions)]
use tower_http::services::ServeDir;
#[cfg(debug_assertions)]
use tower_http::set_header::SetResponseHeaderLayer;

/// Dev only: the browser reloads when a file under `dir` changes, and when the
/// server comes back after a restart (`bacon run-long`). No caching, so an edited module
/// is fetched again. The watcher must live as long as the server.
#[cfg(debug_assertions)]
fn dev_layers(app: Router, dir: &Path) -> (Router, notify::RecommendedWatcher) {
    use axum::http::{HeaderValue, header};
    use notify::{EventKind, RecursiveMode, Watcher};

    let live = tower_livereload::LiveReloadLayer::new();
    let reloader = live.reloader();
    let mut watcher = notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
        // reads (ServeDir opening a file) are access events: not a change
        if ev.is_ok_and(|e| matches!(e.kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_))) {
            reloader.reload();
        }
    })
    .expect("file watcher");
    watcher.watch(dir, RecursiveMode::Recursive).expect("watch the static dir");
    let no_cache = SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (app.layer(no_cache).layer(live), watcher)
}

#[tokio::main]
async fn main() {
    let metrics = std::sync::Arc::new(metrics::Metrics::default());
    let app = api::router(api::Limits::default(), metrics.clone());
    // the page: web/ as is with live reload in debug builds, embedded in release
    #[cfg(debug_assertions)]
    let (app, _watcher, page) = {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../web");
        let (app, watcher) = dev_layers(app.fallback_service(ServeDir::new(&dir)), &dir);
        (app, watcher, format!("from {} (live reload)", dir.display()))
    };
    #[cfg(not(debug_assertions))]
    let (app, page) = (api::secure(app.fallback(assets::serve)), "embedded");

    // BIND: comma separated, e.g. 127.0.0.1:5173,192.168.1.10:5173 to open it from a phone
    let binds = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:5173".into());
    let mut servers = tokio::task::JoinSet::new();
    for addr in binds.split(',').map(str::trim) {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        println!("stackwalk on http://{addr}, page {page}");
        servers.spawn(axum::serve(listener, app.clone()).into_future());
    }
    // METRICS_BIND: Prometheus /metrics on its own address (e.g. 127.0.0.1:9187), never a public one
    if let Ok(addr) = std::env::var("METRICS_BIND") {
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        println!("metrics on http://{addr}/metrics");
        servers.spawn(axum::serve(listener, api::metrics_router(metrics)).into_future());
    }
    if let Some(res) = servers.join_next().await {
        res.expect("server task").expect("server");
    }
}
