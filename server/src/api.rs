//! The JSON API (types and their meaning in `model.rs`), with the limits that keep one request, or a burst of
//! them, from taking the server: input and body size, time per compile, compiles at once.
//! Rate limiting per client is the reverse proxy's job (nginx `limit_req`).
//!
//! `POST /api/compile` answers 200 with a `Scenario`, or `{"error": "..."}` with:
//! - 400: parse / compile errors, taproot, a body that is not JSON, and the size limits of
//!   `scenario.rs` / `paths.rs` (policy conditions, spend paths, stack items in the answer);
//! - 422: JSON that is not a request: a field missing, an unknown kind or wrap;
//! - 413: source text or body over `Limits`; 415: not `Content-Type: application/json`;
//! - 503: over `Limits::time`, waiting for a slot included; 500: the compile panicked.
//!
//! `GET /api/ping`: `{"ok": true, "version": ...}`. Release builds add security headers
//! (`secure`); `/metrics` is on a separate, private listener (`metrics_router`).
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use serde_json::json;
use tokio::sync::Semaphore;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::metrics::Metrics;
use crate::model::{CompileReq, Wrap};
use crate::scenario;

#[derive(Clone)]
pub struct Limits {
    /// bytes of source text; a real policy or script is far below
    pub input: usize,
    /// bytes of the request body
    pub body: usize,
    /// one compile, waiting for a slot included
    pub time: Duration,
    /// compiles running at once; the rest wait for a slot
    pub at_once: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // half the cores: the site next to us keeps the rest
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        Self { input: 4096, body: 16 * 1024, time: Duration::from_secs(5), at_once: (cores / 2).max(1) }
    }
}

#[derive(Clone)]
struct Api {
    limits: Limits,
    slots: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}

fn error(status: StatusCode, msg: String) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn compile(State(api): State<Api>, req: Result<Json<CompileReq>, JsonRejection>) -> Response {
    let Json(req) = match req {
        Ok(r) => r,
        Err(e) => {
            println!("compile rejected status={}", e.status().as_u16());
            // the kind may be what failed to parse
            api.metrics.record("other", e.status().as_u16(), Duration::ZERO);
            return error(e.status(), format!("bad request: {}", e.body_text()));
        }
    };
    let start = Instant::now();
    let metrics = api.metrics.clone();
    let (res, paths) = answer(api, req.clone()).await;
    let took = start.elapsed();
    println!("{}", log_line(&req, res.status(), took, paths));
    metrics.record(req.kind.name(), res.status().as_u16(), took);
    res
}

/// The response, and the number of spend paths when it compiled.
async fn answer(api: Api, req: CompileReq) -> (Response, Option<usize>) {
    let max = api.limits.input;
    if req.text.len() > max {
        return (error(StatusCode::PAYLOAD_TOO_LARGE, format!("input too long: {} bytes (max {max})", req.text.len())), None);
    }
    let run = async move {
        let slot = api.slots.acquire_owned().await.expect("the semaphore is never closed");
        tokio::task::spawn_blocking(move || {
            // the slot is held by the compile itself: one that outlives the timeout
            // still counts against the limit until it is done
            let _slot = slot;
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenario::compile(&req)))
        })
        .await
    };
    match tokio::time::timeout(api.limits.time, run).await {
        Err(_) => (error(StatusCode::SERVICE_UNAVAILABLE, "took too long or the server is busy: try again, or a smaller input".into()), None),
        Ok(Ok(Ok(Ok(s)))) => {
            let paths = s.paths.len();
            (Json(s).into_response(), Some(paths))
        }
        Ok(Ok(Ok(Err(e)))) => (error(StatusCode::BAD_REQUEST, e), None),
        Ok(_) => (error(StatusCode::INTERNAL_SERVER_ERROR, "internal error (panic), see server log".into()), None),
    }
}

/// One line per compile, for the log: what kind of input, how big, how it went. Never the
/// text itself or an error message (both can quote the input).
fn log_line(req: &CompileReq, status: StatusCode, took: Duration, paths: Option<usize>) -> String {
    let (kind, wrap) = (req.kind.name(), req.wrap.map_or("none", Wrap::name));
    let mut line = format!("compile kind={kind} wrap={wrap} len={} status={} ms={}", req.text.len(), status.as_u16(), took.as_millis());
    if let Some(n) = paths {
        line += &format!(" paths={n}");
    }
    line
}

/// Alive, and which version: the page shows it in the footer.
async fn ping() -> Json<serde_json::Value> {
    Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
}

pub fn router(limits: Limits, metrics: Arc<Metrics>) -> Router {
    let api = Api { slots: Arc::new(Semaphore::new(limits.at_once)), limits: limits.clone(), metrics };
    Router::new()
        .route("/api/compile", post(compile))
        .route("/api/ping", get(ping))
        .layer(DefaultBodyLimit::max(limits.body))
        .with_state(api)
}

/// `/metrics` for Prometheus: for a private listener only, it is not on `router`.
pub fn metrics_router(metrics: Arc<Metrics>) -> Router {
    let text = |m: Arc<Metrics>| async move { ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], m.render()) };
    Router::new().route("/metrics", get(move || text(metrics.clone())))
}

/// The page allows only its own scripts, styles, fonts and API (inline styles: the
/// generated markup sets `style="--depth..."`), and no framing.
#[cfg_attr(debug_assertions, allow(dead_code))]
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; \
    connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Security headers on every response. Release only: the dev live reload injects an inline script.
#[cfg_attr(debug_assertions, allow(dead_code))]
pub fn secure(app: Router) -> Router {
    let set = |name: HeaderName, value: &'static str| SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value));
    app.layer(set(header::CONTENT_SECURITY_POLICY, CSP))
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::REFERRER_POLICY, "strict-origin-when-cross-origin"))
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
