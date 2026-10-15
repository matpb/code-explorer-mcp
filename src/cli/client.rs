//! `status` and `healthcheck`: tiny HTTP clients for the running server's own listeners.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use super::{EXIT_FAILURE, load_lenient};

const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// A wildcard listen address is reached through loopback.
fn reachable(addr: SocketAddr) -> SocketAddr {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, addr.port())
}

async fn get(url: &str, timeout: Duration) -> Result<(u16, String), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok((status, body))
}

pub(super) async fn status(config_path: &Path) -> u8 {
    let cfg = match load_lenient(config_path) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let url = format!("http://{}/readyz", reachable(cfg.server.admin_listen));
    match get(&url, STATUS_TIMEOUT).await {
        Ok((code, body)) => {
            match serde_json::from_str::<serde_json::Value>(&body)
                .and_then(|v| serde_json::to_string_pretty(&v))
            {
                Ok(pretty) => println!("{pretty}"),
                Err(_) => println!("{body}"),
            }
            if code == 200 { 0 } else { EXIT_FAILURE }
        }
        Err(e) => {
            eprintln!("cannot reach {url}: {e}");
            EXIT_FAILURE
        }
    }
}

pub(super) async fn healthcheck(config_path: &Path) -> u8 {
    let cfg = match load_lenient(config_path) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let url = format!("http://{}/healthz", reachable(cfg.server.listen));
    match get(&url, HEALTH_TIMEOUT).await {
        Ok((200, _)) => 0,
        Ok((code, _)) => {
            eprintln!("{url} answered {code}");
            EXIT_FAILURE
        }
        Err(e) => {
            eprintln!("cannot reach {url}: {e}");
            EXIT_FAILURE
        }
    }
}
