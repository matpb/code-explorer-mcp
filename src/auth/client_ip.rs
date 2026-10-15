//! Client address derivation behind trusted reverse proxies.

use http::HeaderMap;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WARN_EVERY: Duration = Duration::from_secs(60);
const WARN_TRACKED_MAX: usize = 1024;

static LAST_WARN: Mutex<Option<HashMap<IpAddr, Instant>>> = Mutex::new(None);

/// True when `peer` has not been warned about in the last minute; records the warning time.
fn warn_due(map: &mut HashMap<IpAddr, Instant>, peer: IpAddr, now: Instant) -> bool {
    if map.len() >= WARN_TRACKED_MAX {
        map.retain(|_, t| now.saturating_duration_since(*t) < WARN_EVERY);
    }
    match map.get(&peer) {
        Some(t) if now.saturating_duration_since(*t) < WARN_EVERY => false,
        _ => {
            if map.len() < WARN_TRACKED_MAX {
                map.insert(peer, now);
            }
            true
        }
    }
}

fn warn_missing_header(peer: IpAddr, header: &str) {
    let due = {
        let mut guard = LAST_WARN.lock().unwrap_or_else(|p| p.into_inner());
        warn_due(guard.get_or_insert_with(HashMap::new), peer, Instant::now())
    };
    if due {
        tracing::warn!(
            event = "proxy_without_client_address",
            proxy = %peer,
            header,
            "trusted proxy sent no usable client address; the failed-attempt throttle keys on the proxy"
        );
    }
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|n| n.contains(&ip))
}

fn parse_addr(raw: &str) -> Option<IpAddr> {
    let s = raw.trim();
    let ip = s
        .parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|sa| sa.ip()))
        .or_else(|| {
            s.strip_prefix('[')
                .and_then(|r| r.strip_suffix(']'))
                .and_then(|r| r.parse::<IpAddr>().ok())
        })?;
    Some(ip.to_canonical())
}

/// Returns the real client address; headers count only when `peer` is a trusted proxy.
pub fn derive(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
    header_name: Option<&str>,
) -> IpAddr {
    let peer = peer.to_canonical();
    let Some(name) = header_name else {
        return peer;
    };
    if !is_trusted(peer, trusted) {
        return peer;
    }
    if name.eq_ignore_ascii_case("x-forwarded-for") {
        let mut leftmost = None;
        for token in headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if let Some(ip) = parse_addr(token) {
                if !is_trusted(ip, trusted) {
                    return ip;
                }
                leftmost = Some(ip);
            }
        }
        return leftmost.unwrap_or_else(|| {
            warn_missing_header(peer, name);
            peer
        });
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_addr)
        .unwrap_or_else(|| {
            warn_missing_header(peer, name);
            peer
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn nets(v: &[&str]) -> Vec<IpNet> {
        v.iter().map(|s| s.parse().expect("net")).collect()
    }

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).expect("value"));
        }
        h
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let h = hm(&[("x-forwarded-for", "203.0.113.9")]);
        let got = derive(
            ip("198.51.100.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("X-Forwarded-For"),
        );
        assert_eq!(got, ip("198.51.100.1"));
    }

    #[test]
    fn no_header_name_returns_peer() {
        let h = hm(&[("x-forwarded-for", "203.0.113.9")]);
        let got = derive(ip("10.0.0.1"), &h, &nets(&["10.0.0.0/8"]), None);
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn xff_walks_right_to_left_skipping_trusted() {
        let h = hm(&[("x-forwarded-for", "1.1.1.1, 203.0.113.9, 10.0.0.5")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn xff_spoofed_left_entries_are_ignored() {
        let h = hm(&[("x-forwarded-for", "9.9.9.9, 203.0.113.9")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn xff_multiple_header_lines_are_joined() {
        let h = hm(&[
            ("x-forwarded-for", "9.9.9.9"),
            ("x-forwarded-for", "203.0.113.9, 10.0.0.2"),
        ]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn xff_all_trusted_returns_leftmost() {
        let h = hm(&[("x-forwarded-for", "10.0.0.7, 10.0.0.5")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("10.0.0.7"));
    }

    #[test]
    fn xff_garbage_falls_back_to_peer() {
        let h = hm(&[("x-forwarded-for", "nonsense, also-bad")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn xff_garbage_entries_are_skipped() {
        let h = hm(&[("x-forwarded-for", "203.0.113.9, junk")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn single_header_parses_port_and_brackets() {
        let trusted = nets(&["10.0.0.0/8"]);
        let name = Some("cf-connecting-ip");
        for (raw, want) in [
            ("203.0.113.9", "203.0.113.9"),
            ("203.0.113.9:4444", "203.0.113.9"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ] {
            let h = hm(&[("cf-connecting-ip", raw)]);
            assert_eq!(
                derive(ip("10.0.0.1"), &h, &trusted, name),
                ip(want),
                "{raw}"
            );
        }
    }

    #[test]
    fn single_header_invalid_falls_back_to_peer() {
        let h = hm(&[("cf-connecting-ip", "not an ip")]);
        let got = derive(
            ip("10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("cf-connecting-ip"),
        );
        assert_eq!(got, ip("10.0.0.1"));
    }

    #[test]
    fn ipv4_mapped_peer_is_canonicalized() {
        let h = hm(&[("x-forwarded-for", "203.0.113.9")]);
        let got = derive(
            ip("::ffff:10.0.0.1"),
            &h,
            &nets(&["10.0.0.0/8"]),
            Some("x-forwarded-for"),
        );
        assert_eq!(got, ip("203.0.113.9"));
    }

    #[test]
    fn missing_header_warning_is_rate_limited_per_peer() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let a = ip("10.0.0.1");
        assert!(warn_due(&mut map, a, t0));
        assert!(!warn_due(&mut map, a, t0 + Duration::from_secs(59)));
        assert!(warn_due(
            &mut map,
            ip("10.0.0.2"),
            t0 + Duration::from_secs(1)
        ));
        assert!(warn_due(&mut map, a, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn tracked_peers_are_bounded() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        for i in 0..2000u32 {
            warn_due(&mut map, IpAddr::from(i.to_be_bytes()), t0);
        }
        assert!(map.len() <= WARN_TRACKED_MAX);
    }
}
