//! Bearer-key authentication middleware with client IP derivation and failed-attempt throttling.

pub mod client_ip;
pub mod throttle;

use crate::keys::{AuthFailure, KeyEntry, KeyStore, PendingVerify, Precheck};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
pub use throttle::Throttle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// Per-request identifier, also returned in the `x-request-id` response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

/// The authenticated caller, stored in the request extensions.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub key_id: String,
    pub key_name: String,
    pub repos: Option<Vec<String>>,
    pub client_ip: IpAddr,
    pub request_id: String,
}

impl AuthContext {
    /// True when the key may see `repo_id` (unrestricted keys see every repo).
    pub fn allows(&self, repo_id: &str) -> bool {
        self.repos
            .as_ref()
            .is_none_or(|r| r.iter().any(|x| x == repo_id))
    }

    /// Reads the context the middleware attached to the HTTP request that carried this MCP call.
    pub fn from_request_context(
        ctx: &rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Option<&AuthContext> {
        ctx.extensions
            .get::<http::request::Parts>()?
            .extensions
            .get::<AuthContext>()
    }
}

/// What the middleware reports to an optional metrics hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEvent {
    Failed { reason: &'static str },
    Blocked,
    Busy,
    Ok,
}

pub type MetricsHook = Arc<dyn Fn(AuthEvent) + Send + Sync>;

/// Shared state of the auth layer.
pub struct AuthState {
    pub keys: Arc<KeyStore>,
    pub throttle: Arc<Throttle>,
    pub trusted: Vec<IpNet>,
    pub header: Option<String>,
    pub metrics_hook: Option<MetricsHook>,
    pub verify_permits: Arc<Semaphore>,
    pub verify_wait: Duration,
}

/// How long a request waits for an argon2 slot before getting 503.
pub const VERIFY_WAIT: Duration = Duration::from_secs(2);

impl AuthState {
    pub fn new(
        keys: Arc<KeyStore>,
        throttle: Arc<Throttle>,
        trusted: Vec<IpNet>,
        header: Option<String>,
        metrics_hook: Option<MetricsHook>,
        max_concurrent_verifications: usize,
    ) -> AuthState {
        AuthState {
            keys,
            throttle,
            trusted,
            header,
            metrics_hook,
            verify_permits: Arc::new(Semaphore::new(max_concurrent_verifications.max(1))),
            verify_wait: VERIFY_WAIT,
        }
    }

    fn emit(&self, ev: AuthEvent) {
        if let Some(h) = &self.metrics_hook {
            h(ev);
        }
    }
}

fn new_request_id() -> String {
    let mut b = [0u8; 6];
    rand::fill(&mut b[..]);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn failure_reason(f: AuthFailure) -> &'static str {
    match f {
        AuthFailure::Malformed => "malformed",
        AuthFailure::UnknownId => "unknown_id",
        AuthFailure::WrongSecret => "wrong_secret",
        AuthFailure::Expired => "expired",
        AuthFailure::Disabled => "disabled",
    }
}

fn bearer(req: &Request) -> Option<&str> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

fn json_response(status: StatusCode, body: &'static str, request_id: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

fn retry_after_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

fn blocked_response(
    st: &AuthState,
    client_ip: IpAddr,
    request_id: &str,
    left: Duration,
) -> Response {
    tracing::warn!(event = "auth_blocked", client_ip = %client_ip, request_id = %request_id);
    st.emit(AuthEvent::Blocked);
    let mut resp = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        r#"{"error":"too_many_failed_attempts"}"#,
        request_id,
    );
    if let Ok(v) = HeaderValue::from_str(&retry_after_secs(left).max(1).to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

fn busy_response(st: &AuthState, client_ip: IpAddr, request_id: &str) -> Response {
    tracing::warn!(event = "auth_busy", client_ip = %client_ip, request_id = %request_id);
    st.emit(AuthEvent::Busy);
    let mut resp = json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"busy"}"#,
        request_id,
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    resp
}

fn unauthorized(
    st: &AuthState,
    client_ip: IpAddr,
    request_id: &str,
    reason: &'static str,
) -> Response {
    st.throttle.record_failure(client_ip, Instant::now());
    tracing::warn!(event = "auth_failed", client_ip = %client_ip, reason, request_id = %request_id);
    st.emit(AuthEvent::Failed { reason });
    let mut resp = json_response(
        StatusCode::UNAUTHORIZED,
        r#"{"error":"unauthorized"}"#,
        request_id,
    );
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Bearer realm="code-explorer""#),
    );
    resp
}

/// Takes an argon2 slot at once if one is free, else waits up to `verify_wait`.
async fn acquire_verify_permit(st: &AuthState) -> Option<OwnedSemaphorePermit> {
    match st.verify_permits.clone().try_acquire_owned() {
        Ok(p) => return Some(p),
        Err(TryAcquireError::Closed) => return None,
        Err(TryAcquireError::NoPermits) => {}
    }
    tokio::time::timeout(st.verify_wait, st.verify_permits.clone().acquire_owned())
        .await
        .ok()?
        .ok()
}

enum Verified {
    Entry(Arc<KeyEntry>),
    Reject(Response),
}

/// Hashes on a blocking thread while holding `permit`, which stays held even if the request is dropped.
async fn hash_verify(
    st: &AuthState,
    presented: String,
    pending: PendingVerify,
    permit: OwnedSemaphorePermit,
    client_ip: IpAddr,
    request_id: &str,
) -> Verified {
    let keys = st.keys.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        keys.complete(&presented, pending)
    })
    .await;
    match joined {
        Ok(Ok(entry)) => Verified::Entry(entry),
        Ok(Err(f)) => Verified::Reject(unauthorized(st, client_ip, request_id, failure_reason(f))),
        Err(err) => {
            tracing::error!(error = %err, request_id = %request_id, "key verification task failed");
            Verified::Reject(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"internal_error"}"#,
                request_id,
            ))
        }
    }
}

/// Axum layer for `/mcp`: throttle check, key verification, then the inner service with an `AuthContext`.
pub async fn middleware(
    State(st): State<Arc<AuthState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let client_ip = client_ip::derive(peer.ip(), req.headers(), &st.trusted, st.header.as_deref());
    let request_id = new_request_id();

    if let Some(left) = st.throttle.check(client_ip, Instant::now()) {
        return blocked_response(&st, client_ip, &request_id, left);
    }

    let Some(presented) = bearer(&req).map(str::to_owned) else {
        return unauthorized(&st, client_ip, &request_id, "missing");
    };
    let entry = match st.keys.precheck(&presented) {
        Err(f) => return unauthorized(&st, client_ip, &request_id, failure_reason(f)),
        Ok(Precheck::Verified(entry)) => entry,
        Ok(Precheck::NeedsHash(pending)) => {
            let Some(permit) = acquire_verify_permit(&st).await else {
                return busy_response(&st, client_ip, &request_id);
            };
            if let Some(left) = st.throttle.check(client_ip, Instant::now()) {
                return blocked_response(&st, client_ip, &request_id, left);
            }
            match hash_verify(&st, presented, pending, permit, client_ip, &request_id).await {
                Verified::Entry(entry) => entry,
                Verified::Reject(resp) => return resp,
            }
        }
    };

    st.throttle.record_success(client_ip, Instant::now());
    st.emit(AuthEvent::Ok);
    req.extensions_mut().insert(AuthContext {
        key_id: entry.id.clone(),
        key_name: entry.name.clone(),
        repos: entry.repos.clone(),
        client_ip,
        request_id: request_id.clone(),
    });
    req.extensions_mut().insert(RequestId(request_id.clone()));
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

#[cfg(test)]
mod tests;
