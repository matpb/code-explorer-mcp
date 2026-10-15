//! Failed-attempt throttle keyed by client address, bounded by an LRU.

use crate::config::FailedAttempts;
use lru::LruCache;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const CAPACITY: usize = 65536;

#[derive(Debug, Default)]
struct Entry {
    failures: VecDeque<Instant>,
    blocked_until: Option<Instant>,
    block_level: u32,
}

#[derive(Debug)]
pub struct Throttle {
    max_failures: usize,
    window: Duration,
    base_backoff: Duration,
    max_backoff: Duration,
    ipv6_prefix: u8,
    cache: Mutex<LruCache<IpAddr, Entry>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Throttle {
    pub fn new(cfg: &FailedAttempts) -> Throttle {
        Throttle {
            max_failures: usize::try_from(cfg.max_failures)
                .unwrap_or(usize::MAX)
                .max(1),
            window: cfg.window,
            base_backoff: cfg.base_backoff,
            max_backoff: cfg.max_backoff,
            ipv6_prefix: cfg.ipv6_prefix,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(CAPACITY).unwrap_or(NonZeroUsize::MIN),
            )),
        }
    }

    /// Masks an IPv6 address to `ipv6_prefix` bits; IPv4 is unchanged.
    pub fn group(ip: IpAddr, ipv6_prefix: u8) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                let prefix = u32::from(ipv6_prefix.min(128));
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }

    fn key(&self, ip: IpAddr) -> IpAddr {
        Self::group(ip, self.ipv6_prefix)
    }

    /// Remaining block time for this client, if blocked.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let key = self.key(ip);
        let cache = lock(&self.cache);
        let until = cache.peek(&key)?.blocked_until?;
        until.checked_duration_since(now).filter(|d| !d.is_zero())
    }

    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let key = self.key(ip);
        let mut cache = lock(&self.cache);
        let entry = cache.get_or_insert_mut(key, Entry::default);
        while let Some(&oldest) = entry.failures.front() {
            if now.saturating_duration_since(oldest) > self.window {
                entry.failures.pop_front();
            } else {
                break;
            }
        }
        let still_blocked = entry.blocked_until.is_some_and(|u| u > now);
        if entry.failures.is_empty() && !still_blocked {
            entry.block_level = 0;
            entry.blocked_until = None;
        }
        entry.failures.push_back(now);
        if entry.failures.len() >= self.max_failures {
            let factor = 1u32 << entry.block_level.min(30);
            let backoff = self
                .base_backoff
                .checked_mul(factor)
                .unwrap_or(self.max_backoff)
                .min(self.max_backoff);
            entry.blocked_until = Some(now + backoff);
            entry.block_level = entry.block_level.saturating_add(1);
        }
    }

    /// A success leaves failures inside the window alone; it only clears an entry whose block has expired.
    pub fn record_success(&self, ip: IpAddr, now: Instant) {
        let key = self.key(ip);
        let mut cache = lock(&self.cache);
        let expired = cache
            .peek(&key)
            .and_then(|e| e.blocked_until)
            .is_some_and(|until| until <= now);
        if expired {
            cache.pop(&key);
        }
    }

    /// Number of clients currently blocked. Scans every entry under the lock, so call it on scrape only.
    pub fn blocked_count(&self) -> usize {
        let now = Instant::now();
        lock(&self.cache)
            .iter()
            .filter(|(_, e)| e.blocked_until.is_some_and(|u| u > now))
            .count()
    }

    pub fn len(&self) -> usize {
        lock(&self.cache).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn cfg() -> FailedAttempts {
        FailedAttempts {
            max_failures: 5,
            window: Duration::from_secs(600),
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(900),
            ipv6_prefix: 64,
        }
    }

    fn fail(t: &Throttle, ip: IpAddr, now: Instant, n: usize) {
        for _ in 0..n {
            t.record_failure(ip, now);
        }
    }

    #[test]
    fn five_failures_block_for_base_backoff() {
        let t = Throttle::new(&cfg());
        let a = ip("203.0.113.1");
        let t0 = Instant::now();
        fail(&t, a, t0, 4);
        assert_eq!(t.check(a, t0), None);
        fail(&t, a, t0, 1);
        assert_eq!(t.check(a, t0), Some(Duration::from_secs(2)));
        assert_eq!(t.check(a, t0 + Duration::from_secs(2)), None);
        assert_eq!(t.blocked_count(), 1);
    }

    #[test]
    fn sixth_failure_doubles_the_block() {
        let t = Throttle::new(&cfg());
        let a = ip("203.0.113.1");
        let t0 = Instant::now();
        fail(&t, a, t0, 5);
        let t1 = t0 + Duration::from_secs(3);
        assert_eq!(t.check(a, t1), None);
        fail(&t, a, t1, 1);
        assert_eq!(t.check(a, t1), Some(Duration::from_secs(4)));
        let t2 = t1 + Duration::from_secs(5);
        fail(&t, a, t2, 1);
        assert_eq!(t.check(a, t2), Some(Duration::from_secs(8)));
    }

    #[test]
    fn backoff_is_capped() {
        let mut c = cfg();
        c.max_backoff = Duration::from_secs(5);
        let t = Throttle::new(&c);
        let a = ip("203.0.113.1");
        let mut now = Instant::now();
        fail(&t, a, now, 5);
        for _ in 0..40 {
            now += Duration::from_secs(10);
            fail(&t, a, now, 1);
            let left = t.check(a, now).expect("blocked");
            assert!(left <= Duration::from_secs(5));
        }
        assert_eq!(t.check(a, now), Some(Duration::from_secs(5)));
    }

    #[test]
    fn window_expiry_resets_count_and_level() {
        let t = Throttle::new(&cfg());
        let a = ip("203.0.113.1");
        let t0 = Instant::now();
        fail(&t, a, t0, 6);
        let t1 = t0 + Duration::from_secs(601);
        fail(&t, a, t1, 4);
        assert_eq!(t.check(a, t1), None);
        fail(&t, a, t1, 1);
        assert_eq!(t.check(a, t1), Some(Duration::from_secs(2)));
    }

    #[test]
    fn ipv6_clients_share_a_prefix() {
        let t = Throttle::new(&cfg());
        let t0 = Instant::now();
        fail(&t, ip("2001:db8:1:2::1"), t0, 3);
        fail(&t, ip("2001:db8:1:2:ffff::9"), t0, 2);
        assert!(t.check(ip("2001:db8:1:2::77"), t0).is_some());
        assert!(t.check(ip("2001:db8:1:3::1"), t0).is_none());
    }

    #[test]
    fn group_masks_v6_and_keeps_v4() {
        assert_eq!(
            Throttle::group(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 64),
            ip("2001:db8:1:2::")
        );
        assert_eq!(Throttle::group(ip("2001:db8::1"), 128), ip("2001:db8::1"));
        assert_eq!(Throttle::group(ip("2001:db8::1"), 0), ip("::"));
        assert_eq!(Throttle::group(ip("203.0.113.5"), 64), ip("203.0.113.5"));
    }

    #[test]
    fn lru_is_bounded() {
        let t = Throttle::new(&cfg());
        let t0 = Instant::now();
        for i in 0..70_000u32 {
            t.record_failure(IpAddr::from(i.to_be_bytes()), t0);
        }
        assert!(t.len() <= CAPACITY);
        assert_eq!(t.len(), CAPACITY);
    }

    #[test]
    fn success_inside_the_window_keeps_the_failures() {
        let t = Throttle::new(&cfg());
        let a = ip("203.0.113.1");
        let t0 = Instant::now();
        fail(&t, a, t0, 4);
        t.record_success(a, t0);
        fail(&t, a, t0, 1);
        assert_eq!(t.check(a, t0), Some(Duration::from_secs(2)));
    }

    #[test]
    fn success_after_the_block_expires_resets_the_entry() {
        let t = Throttle::new(&cfg());
        let a = ip("203.0.113.1");
        let t0 = Instant::now();
        fail(&t, a, t0, 5);
        t.record_success(a, t0);
        assert!(
            t.check(a, t0).is_some(),
            "success cannot lift an active block"
        );
        let t1 = t0 + Duration::from_secs(3);
        t.record_success(a, t1);
        assert_eq!(t.len(), 0);
        fail(&t, a, t1, 4);
        assert_eq!(t.check(a, t1), None);
        fail(&t, a, t1, 1);
        assert_eq!(t.check(a, t1), Some(Duration::from_secs(2)));
    }
}
