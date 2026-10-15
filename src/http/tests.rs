use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::*;
use crate::config::{Config, FailedAttempts};
use crate::git::Oid;
use crate::keys;
use crate::redact::Redactor;
use crate::snapshot::{ErrorClass, FileIndex, PullError, Snapshot};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;

#[derive(Clone)]
struct Dummy;

impl ServerHandler for Dummy {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info = Implementation::new("dummy-explorer", "9.9.9");
        info
    }
}

struct Fx {
    dir: tempfile::TempDir,
    cfg: Arc<Config>,
    keys: Arc<KeyStore>,
    key: String,
    auth: Arc<AuthState>,
    metrics: Arc<Metrics>,
}

fn config_text(dir: &Path, extra: &str) -> String {
    let secret = dir.join("secret");
    std::fs::write(&secret, "not-a-real-token\n").expect("write secret");
    format!(
        "version = 1\n[server]\ndata_dir = {:?}\n[auth]\n{extra}\n[credentials.c]\ntype = \"https_token\"\nusername = \"u\"\nsecret_file = {:?}\nexpires = \"2020-01-01\"\n\
         [[repo]]\nid = \"a\"\nhost = \"github\"\npath = \"example-org/a\"\nbranch = \"main\"\ndescription = \"d\"\ncredential = \"c\"\n",
        dir.join("data"),
        secret
    )
}

fn load_cfg(text: &str) -> Arc<Config> {
    Arc::new(Config::parse_unvalidated(text, Path::new("config.toml")).expect("config"))
}

impl Fx {
    fn new(extra_pull: &str) -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut text = config_text(dir.path(), "");
        text.push_str(extra_pull);
        let cfg = load_cfg(&text);
        let path = dir.path().join("keys.toml");
        let (key, entry) = keys::keygen("alice", None, None);
        keys::append_entry(&path, &entry).expect("append");
        let store = KeyStore::new(path, cfg.repo.iter().map(|r| r.id.clone()).collect())
            .expect("key store");
        let auth = Arc::new(AuthState::new(
            store.clone(),
            Arc::new(Throttle::new(&FailedAttempts::default())),
            vec![],
            None,
            None,
            4,
        ));
        Fx {
            dir,
            cfg,
            keys: store,
            key,
            auth,
            metrics: Metrics::new(),
        }
    }

    fn public(&self, origins: &[&str]) -> Router {
        public_router(
            Dummy,
            PublicState {
                auth: self.auth.clone(),
                allowed_origins: origins.iter().map(|s| s.to_string()).collect(),
            },
        )
    }

    fn admin_state(&self) -> AdminState {
        AdminState {
            cfg: self.cfg.clone(),
            registry: Arc::new(Registry::new(&self.cfg)),
            keys: self.keys.clone(),
            metrics: self.metrics.clone(),
            started_at: Utc::now() - ChronoDuration::seconds(5),
            throttle: Some(self.auth.throttle.clone()),
        }
    }
}

fn snapshot(root: &Path, pulled_at: chrono::DateTime<Utc>) -> Arc<Snapshot> {
    Arc::new(Snapshot::new(
        Oid::parse(&"ab12cd34".repeat(5)).expect("oid"),
        pulled_at,
        "subject".into(),
        root.to_path_buf(),
        FileIndex::default(),
        Arc::new(Redactor::empty()),
        0,
        pulled_at,
    ))
}

struct Reply {
    status: StatusCode,
    headers: http::HeaderMap,
    body: String,
}

async fn call(app: &Router, mut req: Request<Body>) -> Reply {
    let peer: SocketAddr = "198.51.100.7:40000".parse().expect("peer");
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.clone().oneshot(req).await.expect("response");
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.expect("body");
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn mcp_post(key: Option<&str>, origin: Option<&str>, body: String) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "explorer.example.com")
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("content-length", body.len());
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    b.body(Body::from(body)).expect("request")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn healthz_needs_no_auth_or_origin() {
    let fx = Fx::new("");
    let app = fx.public(&[]);
    let mut req = get("/healthz");
    req.headers_mut()
        .insert("origin", "https://evil.example.com".parse().expect("hv"));
    let r = call(&app, req).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, "ok");
}

#[tokio::test]
async fn unknown_path_is_json_404() {
    let fx = Fx::new("");
    let r = call(&fx.public(&[]), get("/nope")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.body, r#"{"error":"not_found"}"#);
    assert_eq!(r.headers["content-type"], "application/json");
}

#[tokio::test]
async fn mcp_without_authorization_is_401() {
    let fx = Fx::new("");
    let r = call(&fx.public(&[]), mcp_post(None, None, INIT.into())).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.contains_key("www-authenticate"));
}

#[tokio::test]
async fn disallowed_origin_is_403_even_with_a_valid_key() {
    let fx = Fx::new("");
    let app = fx.public(&["https://app.example.com"]);
    let r = call(
        &app,
        mcp_post(Some(&fx.key), Some("https://evil.example.com"), INIT.into()),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.body, r#"{"error":"origin_not_allowed"}"#);
    let r = call(&app, mcp_post(Some(&fx.key), Some("null"), INIT.into())).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allowed_origin_reaches_the_service() {
    let fx = Fx::new("");
    let app = fx.public(&["https://app.example.com"]);
    let r = call(
        &app,
        mcp_post(
            Some(&fx.key),
            Some("https://APP.example.com:443"),
            INIT.into(),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn initialize_is_answered_with_json() {
    let fx = Fx::new("");
    let r = call(&fx.public(&[]), mcp_post(Some(&fx.key), None, INIT.into())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.headers.contains_key("x-request-id"));
    let v: serde_json::Value = serde_json::from_str(&r.body).expect("json body");
    assert_eq!(v["result"]["serverInfo"]["name"], "dummy-explorer");
}

#[tokio::test]
async fn oversized_body_is_413() {
    let fx = Fx::new("");
    let big = "x".repeat(64 * 1024 + 1);
    let r = call(&fx.public(&[]), mcp_post(Some(&fx.key), None, big)).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn chunked_oversized_body_is_413() {
    let fx = Fx::new("");
    let big = "x".repeat(64 * 1024 + 1);
    let mut req = mcp_post(Some(&fx.key), None, big.clone());
    req.headers_mut().remove("content-length");
    *req.body_mut() = Body::from_stream(futures::stream::iter(vec![Ok::<_, std::io::Error>(
        bytes::Bytes::from(big),
    )]));
    let r = call(&fx.public(&[]), req).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", r.body);
}

#[tokio::test]
async fn readyz_follows_the_repo_lifecycle() {
    let fx = Fx::new("[pull]\nstale_after = \"1h\"\n");
    let st = fx.admin_state();
    let repo = st.registry.get("a").expect("repo").clone();
    let app = admin_router(st);

    let r = call(&app, get("/readyz")).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    let v: serde_json::Value = serde_json::from_str(&r.body).expect("json");
    assert_eq!(v["status"], "initializing");
    assert_eq!(v["repos"][0]["status"], "initializing");
    assert_eq!(v["keys"]["count"], 1);
    assert!(v["keys"]["reload_error"].is_null());
    assert!(v["repos"][0]["commit"].is_null());

    repo.set_snapshot(snapshot(fx.dir.path(), Utc::now()));
    repo.record_success();
    let r = call(&app, get("/readyz")).await;
    assert_eq!(r.status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&r.body).expect("json");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(v["uptime_seconds"].as_u64().expect("uptime") >= 5);
    let repo_v = &v["repos"][0];
    assert_eq!(repo_v["id"], "a");
    assert_eq!(repo_v["status"], "ready");
    assert_eq!(repo_v["commit"], "ab12cd3");
    assert_eq!(repo_v["stale_seconds"], 0);
    assert_eq!(repo_v["scan"]["policy"], "redact");
    assert_eq!(repo_v["scan"]["held"], false);
    assert!(repo_v["credential_expires_in_days"].as_i64().expect("days") < 0);
    assert!(repo_v["last_error"].is_null());
}

#[tokio::test]
async fn readyz_is_degraded_when_a_repo_goes_stale() {
    let fx = Fx::new("[pull]\nstale_after = \"1m\"\n");
    let st = fx.admin_state();
    let repo = st.registry.get("a").expect("repo").clone();
    let app = admin_router(st);
    let old = Utc::now() - ChronoDuration::hours(2);
    repo.set_snapshot(snapshot(fx.dir.path(), old));
    repo.record_restored(old, 0);
    repo.record_failure(PullError {
        class: ErrorClass::Auth,
        message: "fetch failed".into(),
    });
    let r = call(&app, get("/readyz")).await;
    assert_eq!(r.status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&r.body).expect("json");
    assert_eq!(v["status"], "degraded");
    let repo_v = &v["repos"][0];
    assert_eq!(repo_v["status"], "stale");
    assert!(repo_v["stale_seconds"].as_u64().expect("secs") >= 7200);
    assert_eq!(repo_v["consecutive_failures"], 1);
    assert_eq!(repo_v["last_error"]["class"], "auth");
    assert_eq!(repo_v["last_error"]["message"], "fetch failed");
}

#[tokio::test]
async fn readyz_is_degraded_when_the_first_attempt_failed_or_a_scan_is_held() {
    let fx = Fx::new("");
    let st = fx.admin_state();
    let repo = st.registry.get("a").expect("repo").clone();
    let app = admin_router(st);
    repo.record_failure(PullError {
        class: ErrorClass::Network,
        message: "down".into(),
    });
    let v: serde_json::Value =
        serde_json::from_str(&call(&app, get("/readyz")).await.body).expect("json");
    assert_eq!(v["status"], "degraded");
    assert_eq!(v["repos"][0]["status"], "unavailable");

    repo.set_snapshot(snapshot(fx.dir.path(), Utc::now()));
    repo.record_success();
    repo.record_scan(2, true);
    let v: serde_json::Value =
        serde_json::from_str(&call(&app, get("/readyz")).await.body).expect("json");
    assert_eq!(v["status"], "degraded");
    assert_eq!(v["repos"][0]["scan"]["held"], true);
    assert_eq!(v["repos"][0]["scan"]["findings"], 2);
}

#[tokio::test]
async fn metrics_render_with_prometheus_content_type() {
    let fx = Fx::new("");
    let st = fx.admin_state();
    let repo = st.registry.get("a").expect("repo").clone();
    repo.record_scan(3, true);
    let app = admin_router(st);
    let r = call(&app, get("/metrics")).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["content-type"], "text/plain; version=0.0.4");
    assert!(r.body.contains("explorer_build_info"));
    assert!(
        r.body
            .contains("explorer_repo_secret_findings{repo=\"a\"} 3")
    );
    assert!(r.body.contains("explorer_scan_held{repo=\"a\"} 1"));
    assert!(
        r.body
            .contains("explorer_credential_expiry_days{credential=\"c\"}")
    );
    assert!(r.body.contains("explorer_auth_blocked_ips 0"));
}

#[tokio::test]
async fn metrics_route_is_absent_when_disabled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut text = config_text(dir.path(), "");
    text.push_str("[metrics]\nenabled = false\n");
    let cfg = load_cfg(&text);
    let path = dir.path().join("keys.toml");
    std::fs::write(&path, "").expect("keys");
    let st = AdminState {
        keys: KeyStore::new(path, vec![]).expect("store"),
        registry: Arc::new(Registry::new(&cfg)),
        cfg,
        metrics: Metrics::new(),
        started_at: Utc::now(),
        throttle: None,
    };
    let app = admin_router(st);
    assert_eq!(
        call(&app, get("/metrics")).await.status,
        StatusCode::NOT_FOUND
    );
    assert_ne!(
        call(&app, get("/readyz")).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn real_listener_serves_connect_info_and_shuts_down() {
    let fx = Fx::new("");
    let app = fx.public(&[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stop = CancellationToken::new();
    let server = tokio::spawn(serve(listener, app, stop.clone()));
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/mcp");

    let r = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .body(INIT)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 401);

    let r = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .bearer_auth(&fx.key)
        .body(INIT)
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.expect("json");
    assert_eq!(v["result"]["serverInfo"]["name"], "dummy-explorer");

    let r = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("send");
    assert_eq!(r.text().await.expect("text"), "ok");

    drop(client);
    stop.cancel();
    let done = tokio::time::timeout(std::time::Duration::from_secs(15), server)
        .await
        .expect("serve returns after cancel")
        .expect("join");
    assert!(done.is_ok());
}

async fn serve_with_options(options: ServeOptions) -> (SocketAddr, CancellationToken) {
    let fx = Fx::new("");
    let app = fx.public(&[]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stop = CancellationToken::new();
    tokio::spawn({
        let stop = stop.clone();
        async move {
            let _fx = fx;
            let _ = serve_with(listener, app, stop, options).await;
        }
    });
    (addr, stop)
}

async fn closed_within(stream: &mut tokio::net::TcpStream, limit: std::time::Duration) -> bool {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 16];
    match tokio::time::timeout(limit, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

#[tokio::test]
async fn silent_connection_is_closed_after_the_idle_timeout() {
    let (addr, stop) = serve_with_options(ServeOptions {
        idle_timeout: std::time::Duration::from_millis(300),
        ..ServeOptions::default()
    })
    .await;
    let mut silent = tokio::net::TcpStream::connect(addr).await.expect("connect");
    assert!(
        closed_within(&mut silent, std::time::Duration::from_secs(5)).await,
        "idle connection was not closed"
    );

    let client = reqwest::Client::new();
    let r = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .expect("a fresh connection still works");
    assert_eq!(r.text().await.expect("text"), "ok");
    stop.cancel();
}

#[tokio::test]
async fn connection_over_the_cap_is_closed_and_a_freed_slot_is_reusable() {
    let (addr, stop) = serve_with_options(ServeOptions {
        max_connections: 2,
        ..ServeOptions::default()
    })
    .await;
    let held_a = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut held_b = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut over = tokio::net::TcpStream::connect(addr).await.expect("connect");
    assert!(
        closed_within(&mut over, std::time::Duration::from_secs(5)).await,
        "the third connection should be closed"
    );
    assert!(
        !closed_within(&mut held_b, std::time::Duration::from_millis(300)).await,
        "connections under the cap stay open"
    );

    drop(held_a);
    let mut served = false;
    for _ in 0..50 {
        let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if s.write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .await
            .is_ok()
        {
            let mut out = String::new();
            let _ = s.read_to_string(&mut out).await;
            if out.contains("200 OK") {
                served = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        served,
        "a slot freed by a closed connection must be reusable"
    );
    stop.cancel();
}
