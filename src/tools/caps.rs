//! Output caps: long-line cutting, response-size fitting and small formatting helpers.

use std::borrow::Cow;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

/// Cuts `s` after `max_chars` characters; the flag says whether anything was cut.
pub fn cut_line(s: &str, max_chars: usize) -> (Cow<'_, str>, bool) {
    match s.char_indices().nth(max_chars) {
        None => (Cow::Borrowed(s), false),
        Some((idx, _)) => (
            Cow::Owned(format!("{} [cut at {max_chars} chars]", &s[..idx])),
            true,
        ),
    }
}

fn json_len(v: &Value) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

/// Drops trailing items until the built JSON is at most `max_bytes`; the flag says whether any were dropped.
pub fn fit_response<T: Serialize>(
    items: &mut Vec<T>,
    build: impl Fn(&[T]) -> Value,
    max_bytes: usize,
) -> (Value, bool) {
    let full = build(items);
    if json_len(&full) <= max_bytes {
        return (full, false);
    }
    let (mut lo, mut hi) = (0usize, items.len().saturating_sub(1));
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if json_len(&build(&items[..mid])) <= max_bytes {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    items.truncate(lo);
    (build(items), true)
}

/// `48 KiB`, `9.1 MiB`: one decimal at most, trailing `.0` dropped.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes} B");
    }
    let rounded = format!("{value:.1}");
    let trimmed = rounded.strip_suffix(".0").unwrap_or(&rounded);
    format!("{trimmed} {}", UNITS[unit])
}

/// `45s`, `12m`, `5h`, `3d`.
pub fn human_age(secs: u64) -> String {
    match secs {
        0..=119 => format!("{secs}s"),
        120..=7199 => format!("{}m", secs / 60),
        7200..=172_799 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

pub fn human_duration(d: Duration) -> String {
    humantime::format_duration(d).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cut_line_respects_char_boundaries() {
        let (out, cut) = cut_line("héllo wörld", 4);
        assert!(cut);
        assert_eq!(out, "héll [cut at 4 chars]");
        let (out, cut) = cut_line("short", 5);
        assert!(!cut);
        assert_eq!(out, "short");
    }

    #[test]
    fn fit_response_drops_trailing_items() {
        let mut items: Vec<String> = (0..50).map(|i| format!("item-{i:04}")).collect();
        let build = |s: &[String]| json!({ "items": s });
        let (full, cut) = fit_response(&mut items.clone(), build, 100_000);
        assert!(!cut);
        assert_eq!(full["items"].as_array().map(Vec::len), Some(50));
        let (v, cut) = fit_response(&mut items, build, 200);
        assert!(cut);
        assert!(
            serde_json::to_vec(&v)
                .map(|b| b.len())
                .unwrap_or(usize::MAX)
                <= 200
        );
        assert_eq!(items.len(), v["items"].as_array().map_or(0, Vec::len));
        assert!(!items.is_empty() && items.len() < 50);
        assert_eq!(items[0], "item-0000");
    }

    #[test]
    fn fit_response_can_drop_everything() {
        let mut items = vec!["x".repeat(500)];
        let (v, cut) = fit_response(&mut items, |s| json!({ "items": s }), 50);
        assert!(cut);
        assert!(items.is_empty());
        assert_eq!(v["items"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn sizes_and_ages() {
        assert_eq!(human_size(48 * 1024), "48 KiB");
        assert_eq!(human_size(4 * 1024 * 1024), "4 MiB");
        assert_eq!(human_size(9_542_041), "9.1 MiB");
        assert_eq!(human_size(12), "12 B");
        assert_eq!(human_age(45), "45s");
        assert_eq!(human_age(3600), "60m");
        assert_eq!(human_age(3 * 3600), "3h");
        assert_eq!(human_age(3 * 86_400), "3d");
    }
}
