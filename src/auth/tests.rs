use super::*;
use crate::config::FailedAttempts;
use crate::keys;
use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::routing::post;
use http::Request as HttpRequest;
use std::sync::Mutex;
use tower::ServiceExt;

struct Harness {
    app: Router,
    key: String,
    events: Arc<Mutex<Vec<AuthEvent>>>,
    _dir: tempfile::TempDir,
}

async fn whoami(
    Extension(ctx): Extension<AuthContext>,
    Extension(rid): Extension<RequestId>,
) -> String {
    format!(
        "{}|{:?}|{}|{}",
        ctx.key_name,
        ctx.repos,
        ctx.client_ip,
        u8::from(rid.0 == ctx.request_id)
    )
}

fn harness(trusted: &[&str], header: Option<&str>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys.toml");
    let (key, entry) = keys::keygen("alice", Some(vec!["repo-a".to_string()]), None);
    keys::append_entry(&path, &entry).expect("append");
    let store = KeyStore::new(path, vec![]).expect("store");
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let st = Arc::new(AuthState {
        keys: store,
        throttle: Arc::new(Throttle::new(&FailedAttempts::default())),
        trusted: trusted.iter().map(|s| s.parse().expect("net")).collect(),
        header: header.map(str::to_string),
        metrics_hook: Some(Arc::new(move |e| {
            sink.lock().expect("lock").push(e);
        })),
    });
    let app = Router::new()
        .route("/mcp", post(whoami))
        .layer(axum::middleware::from_fn_with_state(st, middleware));
    Harness {
        app,
        key,
        events,
        _dir: dir,
    }
}

async fn send(
    app: &Router,
    peer: &str,
    auth: Option<&str>,
    xff: Option<&str>,
) -> (StatusCode, http::HeaderMap, String) {
    let mut b = HttpRequest::builder().method("POST").uri("/mcp");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(x) = xff {
        b = b.header("x-forwarded-for", x);
    }
    let mut req = b.body(Body::empty()).expect("request");
    let addr: SocketAddr = format!("{peer}:50000").parse().expect("peer");
    req.extensions_mut().insert(ConnectInfo(addr));
    let resp = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 16).await.expect("body");
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn bad_key(key: &str) -> String {
    let mut k = key.to_string();
    let last = k.pop().expect("non-empty");
    k.push(if last == 'A' { 'B' } else { 'A' });
    k
}

#[tokio::test]
async fn valid_key_reaches_handler_with_context() {
    let h = harness(&[], None);
    let (status, headers, body) = send(
        &h.app,
        "198.51.100.1",
        Some(&format!("Bearer {}", h.key)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "alice|Some([\"repo-a\"])|198.51.100.1|1");
    assert_eq!(headers["x-request-id"].len(), 12);
    assert_eq!(*h.events.lock().expect("lock"), vec![AuthEvent::Ok]);
}

#[tokio::test]
async fn missing_header_is_401_with_challenge() {
    let h = harness(&[], None);
    let (status, headers, body) = send(&h.app, "198.51.100.1", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        headers["www-authenticate"],
        r#"Bearer realm="code-explorer""#
    );
    assert!(headers.contains_key("x-request-id"));
    assert_eq!(body, r#"{"error":"unauthorized"}"#);
    assert_eq!(
        *h.events.lock().expect("lock"),
        vec![AuthEvent::Failed { reason: "missing" }]
    );
}

#[tokio::test]
async fn wrong_scheme_and_empty_token_are_missing() {
    let h = harness(&[], None);
    for a in ["Basic abc", "Bearer ", "Bearer"] {
        let (status, _, _) = send(&h.app, "198.51.100.1", Some(a), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{a}");
    }
    let evs = h.events.lock().expect("lock").clone();
    assert!(
        evs.iter()
            .all(|e| *e == AuthEvent::Failed { reason: "missing" })
    );
}

#[tokio::test]
async fn wrong_secret_is_401() {
    let h = harness(&[], None);
    let auth = format!("Bearer {}", bad_key(&h.key));
    let (status, headers, body) = send(&h.app, "198.51.100.1", Some(&auth), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("www-authenticate"));
    assert!(!body.contains(&h.key));
    assert_eq!(
        *h.events.lock().expect("lock"),
        vec![AuthEvent::Failed {
            reason: "wrong_secret"
        }]
    );
}

#[tokio::test]
async fn sixth_attempt_is_429_without_key_check() {
    let h = harness(&[], None);
    for _ in 0..5 {
        let (status, _, _) = send(&h.app, "198.51.100.1", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let auth = format!("Bearer {}", h.key);
    let (status, headers, body) = send(&h.app, "198.51.100.1", Some(&auth), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = headers["retry-after"]
        .to_str()
        .expect("str")
        .parse()
        .expect("num");
    assert!((1..=2).contains(&retry));
    assert_eq!(body, r#"{"error":"too_many_failed_attempts"}"#);
    assert_eq!(
        h.events.lock().expect("lock").last(),
        Some(&AuthEvent::Blocked)
    );
    let (status, _, _) = send(&h.app, "198.51.100.2", Some(&auth), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn xff_is_honored_only_from_a_trusted_peer() {
    let h = harness(&["10.0.0.0/8"], Some("x-forwarded-for"));
    for _ in 0..5 {
        let (status, _, _) = send(&h.app, "10.0.0.1", None, Some("203.0.113.7")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let auth = format!("Bearer {}", h.key);
    let (status, _, _) = send(&h.app, "10.0.0.1", Some(&auth), Some("203.0.113.7")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _, body) = send(&h.app, "10.0.0.1", Some(&auth), Some("203.0.113.8")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("|203.0.113.8|"), "{body}");
}

#[tokio::test]
async fn xff_from_an_untrusted_peer_cannot_dodge_the_throttle() {
    let h = harness(&["10.0.0.0/8"], Some("x-forwarded-for"));
    for i in 0..5 {
        let xff = format!("203.0.113.{i}");
        let (status, _, _) = send(&h.app, "198.51.100.1", None, Some(&xff)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = send(&h.app, "198.51.100.1", None, Some("203.0.113.99")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn allows_respects_repo_scope() {
    let mut ctx = AuthContext {
        key_id: "abcdefgh".into(),
        key_name: "n".into(),
        repos: Some(vec!["a".into()]),
        client_ip: "127.0.0.1".parse().expect("ip"),
        request_id: "r".into(),
    };
    assert!(ctx.allows("a"));
    assert!(!ctx.allows("b"));
    ctx.repos = None;
    assert!(ctx.allows("b"));
}
