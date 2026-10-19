use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::*;

async fn post(limits: Limits, content_type: &str, body: String) -> (StatusCode, String) {
    let req = Request::post("/api/compile").header(header::CONTENT_TYPE, content_type).body(Body::from(body)).unwrap();
    let res = router(limits, Arc::default()).oneshot(req).await.unwrap();
    let status = res.status();
    (status, String::from_utf8(to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap())
}

async fn compile_json(limits: Limits, text: &str) -> (StatusCode, String) {
    post(limits, "application/json", serde_json::json!({ "kind": "policy", "text": text }).to_string()).await
}

#[tokio::test]
async fn compiles_a_policy() {
    let (status, body) = compile_json(Limits::default(), "pk(A)").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"descriptor\""));
}

#[tokio::test]
async fn a_compile_error_is_json() {
    let (status, body) = compile_json(Limits::default(), "pk(").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.starts_with("{\"error\":"), "{body}");
}

#[tokio::test]
async fn only_json_is_accepted() {
    // a cross-site form can post text/plain without a CORS preflight
    let (status, body) = post(Limits::default(), "text/plain", r#"{"kind":"policy","text":"pk(A)"}"#.into()).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(body.starts_with("{\"error\":"), "{body}");
}

#[tokio::test]
async fn long_input_is_refused_before_compiling() {
    let limits = Limits { input: 10, ..Limits::default() };
    let (status, body) = compile_json(limits, "and(pk(A),pk(B))").await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.contains("input too long"), "{body}");
}

#[tokio::test]
async fn large_body_is_refused() {
    let limits = Limits { body: 64, ..Limits::default() };
    let (status, body) = compile_json(limits, &"x".repeat(100)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.starts_with("{\"error\":"), "{body}");
}

#[tokio::test]
async fn a_slow_compile_times_out() {
    // an or-chain of 10 keys: about a second for the policy compiler, in release
    let chain = "or(pk(A),or(pk(B),or(pk(C),or(pk(D),or(pk(E),or(pk(F),or(pk(G),or(pk(H),or(pk(I),pk(J))))))))))";
    let limits = Limits { time: Duration::from_millis(10), ..Limits::default() };
    let (status, body) = compile_json(limits, chain).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("too long"), "{body}");
}

#[tokio::test]
async fn compiles_wait_for_a_free_slot() {
    // no slots at all: the request waits, then times out instead of running
    let limits = Limits { at_once: 0, time: Duration::from_millis(50), ..Limits::default() };
    let (status, _) = compile_json(limits, "pk(A)").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn a_log_line_has_no_user_text() {
    let req = |kind: &str, text: &str, wrap: Option<&str>| CompileReq { kind: kind.into(), text: text.into(), wrap: wrap.map(Into::into) };
    let line = log_line(&req("policy", "pk(SECRET)", Some("sh")), StatusCode::OK, Duration::from_millis(12), Some(3));
    assert_eq!(line, "compile kind=policy wrap=sh len=10 status=200 ms=12 paths=3");
    // what the client sends as kind / wrap is not trusted: no new lines, no forged fields
    let line = log_line(&req("policy\ncompile kind=fake", "x", Some("a b")), StatusCode::BAD_REQUEST, Duration::ZERO, None);
    assert_eq!(line, "compile kind=other wrap=other len=1 status=400 ms=0");
}

#[tokio::test]
async fn security_headers_are_set() {
    let app = secure(router(Limits::default(), Arc::default()));
    let res = app.oneshot(Request::get("/api/ping").body(Body::empty()).unwrap()).await.unwrap();
    let h = res.headers();
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "strict-origin-when-cross-origin");
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
}

async fn get_text(app: Router, path: &str) -> (StatusCode, String) {
    let res = app.oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    (status, String::from_utf8(to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap())
}

#[tokio::test]
async fn metrics_count_requests_by_kind_and_status() {
    let metrics = Arc::new(Metrics::default());
    for text in ["pk(A)", "pk(A)", "pk("] {
        let body = serde_json::json!({ "kind": "policy", "text": text }).to_string();
        let req = Request::post("/api/compile").header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap();
        router(Limits::default(), metrics.clone()).oneshot(req).await.unwrap();
    }
    let (status, text) = get_text(metrics_router(metrics), "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("stackwalk_requests_total{kind=\"policy\",status=\"200\"} 2\n"), "{text}");
    assert!(text.contains("stackwalk_requests_total{kind=\"policy\",status=\"400\"} 1\n"), "{text}");
    assert!(text.contains("stackwalk_compile_seconds_count 3\n"), "{text}");
    assert!(text.contains("# TYPE stackwalk_requests_total counter"), "{text}");
}

#[tokio::test]
async fn metrics_are_not_on_the_public_router() {
    let (status, _) = get_text(router(Limits::default(), Arc::default()), "/metrics").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
