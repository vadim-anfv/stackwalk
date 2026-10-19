//! The page, embedded at build time (`build.rs`): what a release binary serves.
//! Debug builds serve `web/` from disk instead (live reload), see `main.rs`.
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    let Some((_, content_type, bytes)) = FILES.iter().find(|(name, _, _)| *name == path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // revalidate every time; unchanged since this build -> 304, no body
    let fresh = headers.get(header::IF_NONE_MATCH).is_some_and(|v| v.as_bytes() == ETAG.as_bytes());
    let common = [(header::ETAG, HeaderValue::from_static(ETAG)), (header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))];
    if fresh {
        return (StatusCode::NOT_MODIFIED, common).into_response();
    }
    (common, [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))], *bytes).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn get(path: &str, etag: Option<&str>) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(e) = etag {
            headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(e).unwrap());
        }
        serve(path.parse().unwrap(), headers).await
    }

    #[tokio::test]
    async fn root_is_the_page() {
        let res = get("/", None).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        let body = String::from_utf8(to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("<title>"));
    }

    #[tokio::test]
    async fn modules_and_unknown_paths() {
        assert_eq!(get("/app.js", None).await.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(get("/nope.js", None).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(get("/../Cargo.toml", None).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn etag_revalidates() {
        let res = get("/style.css", None).await;
        let etag = res.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(get("/style.css", Some(&etag)).await.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(get("/style.css", Some("\"old\"")).await.status(), StatusCode::OK);
    }
}
