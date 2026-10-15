//! Origin header check: exact scheme, host and port match against `allowed_origins`.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

/// Normalized allow-list built once from `server.allowed_origins`.
#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    allowed: HashSet<String>,
}

impl OriginPolicy {
    pub fn new(origins: &[String]) -> OriginPolicy {
        OriginPolicy {
            allowed: origins.iter().filter_map(|o| normalize(o)).collect(),
        }
    }

    pub fn allows(&self, origin: &str) -> bool {
        normalize(origin).is_some_and(|o| self.allowed.contains(&o))
    }
}

/// Lowercased `scheme://host:port` with the default port made explicit, or `null`.
pub fn normalize(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s == "null" {
        return Some(s);
    }
    let s = s.strip_suffix('/').unwrap_or(&s);
    let uri: axum::http::Uri = s.parse().ok()?;
    let scheme = uri.scheme_str()?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = uri.authority()?;
    if authority.as_str().contains('@') || !matches!(uri.path(), "" | "/") || uri.query().is_some()
    {
        return None;
    }
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    let port = authority.port_u16().unwrap_or(default_port);
    Some(format!("{scheme}://{host}:{port}"))
}

fn forbidden() -> Response {
    let mut resp = Response::new(axum::body::Body::from(r#"{"error":"origin_not_allowed"}"#));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Rejects a present `Origin` that is not allowed; requests without one pass.
pub async fn check(State(policy): State<Arc<OriginPolicy>>, req: Request, next: Next) -> Response {
    let mut values = req.headers().get_all(header::ORIGIN).iter();
    if let Some(first) = values.next() {
        let ok =
            values.next().is_none() && first.to_str().is_ok_and(|origin| policy.allows(origin));
        if !ok {
            return forbidden();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(list: &[&str]) -> OriginPolicy {
        OriginPolicy::new(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn default_ports_and_case_are_normalized() {
        let p = policy(&["https://App.Example.com", "http://localhost:3000/"]);
        assert!(p.allows("https://app.example.com:443"));
        assert!(p.allows("HTTPS://APP.EXAMPLE.COM"));
        assert!(p.allows("http://localhost:3000"));
        assert!(!p.allows("http://app.example.com"));
        assert!(!p.allows("https://app.example.com:8443"));
        assert!(!p.allows("https://evil.example.com"));
        assert!(!p.allows("https://app.example.com.evil.test"));
    }

    #[test]
    fn malformed_origins_never_match() {
        let p = policy(&["https://app.example.com"]);
        assert!(!p.allows("https://app.example.com/path"));
        assert!(!p.allows("https://user@app.example.com"));
        assert!(!p.allows("ftp://app.example.com"));
        assert!(!p.allows(""));
        assert!(!p.allows("null"));
    }

    #[test]
    fn null_passes_only_when_listed() {
        assert!(policy(&["null"]).allows("null"));
        assert!(!policy(&[]).allows("null"));
    }

    #[test]
    fn ipv6_hosts_compare_with_port() {
        let p = policy(&["http://[::1]:8080"]);
        assert!(p.allows("http://[::1]:8080"));
        assert!(!p.allows("http://[::1]:80"));
    }
}
