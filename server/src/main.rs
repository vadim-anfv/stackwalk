// debug builds serve web/ from disk; the embedded page is for release (and the tests)
#[cfg_attr(debug_assertions, allow(dead_code))]
mod assets;
mod keys;
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

// the deploy build of web/ that build.rs embeds: tested with the crate
#[cfg(test)]
#[path = "../build/web.rs"]
mod web_build;

#[cfg(debug_assertions)]
use std::path::Path;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde_json::json;
#[cfg(debug_assertions)]
use tower_http::services::ServeDir;
#[cfg(debug_assertions)]
use tower_http::set_header::SetResponseHeaderLayer;

use model::CompileReq;

fn bad(msg: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

async fn compile(body: String) -> Response {
    let req: CompileReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return bad(format!("bad request: {e}")),
    };
    let res = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenario::compile(&req)))
    })
    .await;
    match res {
        Ok(Ok(Ok(s))) => Json(s).into_response(),
        Ok(Ok(Err(e))) => bad(e),
        _ => bad("internal error (panic), see server log".into()),
    }
}

async fn ping() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

/// Dev only: the browser reloads when a file under `dir` changes, and when the
/// server comes back after a restart (bacon). No caching, so an edited module
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
    let app = Router::new().route("/api/compile", post(compile)).route("/api/ping", get(ping));
    // the page: web/ as is with live reload in debug builds, embedded in release
    #[cfg(debug_assertions)]
    let (app, _watcher, page) = {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../web");
        let (app, watcher) = dev_layers(app.fallback_service(ServeDir::new(&dir)), &dir);
        (app, watcher, format!("from {} (live reload)", dir.display()))
    };
    #[cfg(not(debug_assertions))]
    let (app, page) = (app.fallback(assets::serve), "embedded");

    // BIND: comma separated, e.g. 127.0.0.1:5173,192.168.1.10:5173 to open it from a phone
    let binds = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:5173".into());
    let mut servers = tokio::task::JoinSet::new();
    for addr in binds.split(',').map(str::trim) {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        println!("stackwalk on http://{addr}, page {page}");
        servers.spawn(axum::serve(listener, app.clone()).into_future());
    }
    if let Some(res) = servers.join_next().await {
        res.expect("server task").expect("server");
    }
}
