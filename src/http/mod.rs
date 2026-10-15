//! HTTP edge: public router (`/mcp`, `/healthz`), admin router (`/readyz`, `/metrics`) and the accept loop.

pub mod origin;
pub mod readyz;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{any_service, get};
use chrono::{DateTime, Utc};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rmcp::ServerHandler;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::Service;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::{self, AuthState, Throttle};
use crate::config::Config;
use crate::keys::KeyStore;
use crate::metrics::Metrics;
use crate::snapshot::{Registry, RepoStatus};

pub use readyz::{ReadyzBody, readyz};

const MAX_BODY_BYTES: usize = 64 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// State of the public listener.
pub struct PublicState {
    pub auth: Arc<AuthState>,
    pub allowed_origins: Vec<String>,
    pub metrics: Arc<Metrics>,
}

/// State of the admin listener; `throttle` feeds the blocked-IP gauge.
pub struct AdminState {
    pub cfg: Arc<Config>,
    pub registry: Arc<Registry>,
    pub keys: Arc<KeyStore>,
    pub metrics: Arc<Metrics>,
    pub started_at: DateTime<Utc>,
    pub throttle: Option<Arc<Throttle>>,
}

fn json(status: StatusCode, body: &'static str) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

async fn not_found() -> Response {
    json(StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn timeout(req: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => json(
            StatusCode::GATEWAY_TIMEOUT,
            r#"{"error":"request_timeout"}"#,
        ),
    }
}

fn is_length_limit(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if e.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        cur = e.source();
    }
    false
}

/// Reads the body up to the cap so a chunked oversize upload gets 413 instead of a handler error.
async fn buffer_body(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Err(e) if is_length_limit(&e) => json(
            StatusCode::PAYLOAD_TOO_LARGE,
            r#"{"error":"payload_too_large"}"#,
        ),
        Err(_) => json(StatusCode::BAD_REQUEST, r#"{"error":"bad_request"}"#),
    }
}

/// Router for the public listener. Layers from the outside: trace, body limit, Origin, auth, timeout, body buffer.
pub fn public_router<S>(handler: S, st: PublicState) -> Router
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let mut mcp_config = StreamableHttpServerConfig::default()
        .with_max_request_body_bytes(MAX_BODY_BYTES)
        .disable_allowed_hosts()
        .disable_allowed_origins();
    mcp_config.legacy_session_mode = false;
    mcp_config.json_response = true;
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(NeverSessionManager::default()),
        mcp_config,
    );
    let origins = Arc::new(origin::OriginPolicy::new(&st.allowed_origins));
    let mcp = Router::new()
        .route("/mcp", any_service(service))
        .route_layer(from_fn(buffer_body))
        .route_layer(from_fn(timeout))
        .route_layer(from_fn_with_state(st.auth.clone(), auth::middleware))
        .route_layer(from_fn_with_state(origins, origin::check))
        .route_layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(mcp)
        .fallback(not_found)
        .layer(TraceLayer::new_for_http())
}

/// Router for the admin listener: `/readyz`, and `/metrics` when enabled.
pub fn admin_router(st: AdminState) -> Router {
    let metrics_enabled = st.cfg.metrics.enabled;
    let mut router = Router::new().route("/readyz", get(readyz_handler));
    if metrics_enabled {
        router = router.route("/metrics", get(metrics_handler));
    }
    router
        .fallback(not_found)
        .with_state(Arc::new(st))
        .layer(TraceLayer::new_for_http())
}

async fn readyz_handler(State(st): State<Arc<AdminState>>) -> Response {
    let (code, body) = readyz(&st);
    (code, axum::Json(body)).into_response()
}

fn refresh_gauges(st: &AdminState) {
    let now = Utc::now();
    let today = now.date_naive();
    for repo in st.registry.iter() {
        let id = &repo.cfg.id;
        let status = repo.status_word(st.cfg.pull.stale_after, now);
        let pull = repo.status();
        st.metrics.set_repo_stale(
            id,
            matches!(status, RepoStatus::Stale | RepoStatus::Unavailable),
        );
        st.metrics.set_repo_findings(id, pull.scan_findings);
        st.metrics.set_scan_held(id, pull.scan_held);
    }
    for (name, cred) in &st.cfg.credentials {
        if let Some(expires) = cred.expires() {
            st.metrics
                .set_credential_expiry(name, readyz::expiry_days(expires, today) as f64);
        }
    }
    if let Some(t) = &st.throttle {
        st.metrics.set_blocked_ips(t.blocked_count());
    }
}

async fn metrics_handler(State(st): State<Arc<AdminState>>) -> Response {
    refresh_gauges(&st);
    let mut resp = Response::new(axum::body::Body::from(st.metrics.render()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    resp
}

/// Accept loop with HTTP/1 and HTTP/2 auto detection; on cancel it stops accepting and drains for up to 10s.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let service = match make_service.call(peer).await {
            Ok(s) => s,
            Err(never) => match never {},
        };
        let conn = builder
            .clone()
            .serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(service))
            .into_owned();
        let stop = shutdown.clone();
        let guard = done_tx.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let mut conn = std::pin::pin!(conn);
            let result = tokio::select! {
                r = conn.as_mut() => r,
                _ = stop.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, peer = %peer, "connection ended with an error");
            }
        });
    }
    drop(listener);
    drop(done_tx);
    if tokio::time::timeout(SHUTDOWN_GRACE, done_rx.recv())
        .await
        .is_err()
    {
        tracing::warn!("graceful shutdown deadline reached, dropping open connections");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
