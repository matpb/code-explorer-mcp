//! Bearer-key authentication middleware with client IP derivation and failed-attempt throttling.

pub mod client_ip;
pub mod throttle;

use crate::keys::{AuthFailure, KeyStore};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
pub use throttle::Throttle;

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
}

impl AuthState {
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
        tracing::warn!(event = "auth_blocked", client_ip = %client_ip, request_id = %request_id);
        st.emit(AuthEvent::Blocked);
        let mut resp = json_response(
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":"too_many_failed_attempts"}"#,
            &request_id,
        );
        if let Ok(v) = HeaderValue::from_str(&retry_after_secs(left).max(1).to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }

    let outcome = match bearer(&req).map(str::to_owned) {
        None => Err("missing"),
        Some(presented) => {
            let keys = st.keys.clone();
            match tokio::task::spawn_blocking(move || keys.verify(&presented)).await {
                Ok(Ok(entry)) => Ok(entry),
                Ok(Err(f)) => Err(failure_reason(f)),
                Err(err) => {
                    tracing::error!(error = %err, request_id = %request_id, "key verification task failed");
                    return json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"internal_error"}"#,
                        &request_id,
                    );
                }
            }
        }
    };

    let entry = match outcome {
        Ok(entry) => entry,
        Err(reason) => {
            st.throttle.record_failure(client_ip, Instant::now());
            tracing::warn!(
                event = "auth_failed",
                client_ip = %client_ip,
                reason,
                request_id = %request_id
            );
            st.emit(AuthEvent::Failed { reason });
            let mut resp = json_response(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"unauthorized"}"#,
                &request_id,
            );
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="code-explorer""#),
            );
            return resp;
        }
    };

    st.throttle.record_success(client_ip);
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
