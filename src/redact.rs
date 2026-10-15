//! Masks exact secret values found by the scanner, in strings and in raw file bytes.

use aho_corasick::{AhoCorasick, MatchKind};
use std::borrow::Cow;
use std::collections::HashSet;

const MIN_SECRET_LEN: usize = 6;

#[derive(Debug)]
enum Matcher {
    Automaton(AhoCorasick),
    /// Fallback if the automaton cannot be built: longest patterns replaced first.
    Sequential,
}

/// Replaces known secret values with `[REDACTED:<rule_id>]`.
#[derive(Debug)]
pub struct Redactor {
    patterns: Vec<String>,
    replacements: Vec<String>,
    secrets: usize,
    matcher: Option<Matcher>,
}

/// One marker per line of `secret`, keeping its line breaks so line numbers do not shift.
fn block_replacement(secret: &str, marker: &str) -> String {
    secret
        .split('\n')
        .map(|line| match (line.is_empty(), line.ends_with('\r')) {
            (true, _) => String::new(),
            (false, true) => format!("{marker}\r"),
            (false, false) => marker.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A PEM armor line such as `-----BEGIN RSA PRIVATE KEY-----` is too common to be a pattern.
fn is_pem_boundary(line: &str) -> bool {
    line.len() > 10 && line.starts_with("-----") && line.ends_with("-----")
}

/// Each line of a multi-line secret that is long and distinctive enough to match on its own.
pub fn secret_lines(secret: &str) -> impl Iterator<Item = &str> {
    let multi = secret.contains('\n');
    secret
        .lines()
        .filter(move |_| multi)
        .map(str::trim)
        .filter(|l| l.len() >= MIN_SECRET_LEN && !is_pem_boundary(l))
}

impl Redactor {
    /// Builds a redactor from `(secret, rule_id)` pairs; secrets under 6 bytes are ignored.
    /// A multi-line secret also adds each of its lines, so per-line output is masked too.
    pub fn new(findings: &[(String, String)]) -> Self {
        let mut seen = HashSet::new();
        let mut secrets = HashSet::new();
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        for (secret, rule_id) in findings {
            if secret.len() < MIN_SECRET_LEN || !secrets.insert(secret.as_str()) {
                continue;
            }
            let marker = format!("[REDACTED:{rule_id}]");
            if seen.insert(secret.clone()) {
                patterns.push(secret.clone());
                replacements.push(block_replacement(secret, &marker));
            }
            for line in secret_lines(secret) {
                if seen.insert(line.to_owned()) {
                    patterns.push(line.to_owned());
                    replacements.push(marker.clone());
                }
            }
        }
        let secret_count = secrets.len();
        if patterns.is_empty() {
            return Self::empty();
        }
        let matcher = match AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
        {
            Ok(ac) => Matcher::Automaton(ac),
            Err(err) => {
                tracing::error!(error = %err, "redaction automaton build failed, using sequential fallback");
                let mut order: Vec<usize> = (0..patterns.len()).collect();
                order.sort_by_key(|&i| std::cmp::Reverse(patterns[i].len()));
                patterns = order.iter().map(|&i| patterns[i].clone()).collect();
                replacements = order.iter().map(|&i| replacements[i].clone()).collect();
                Matcher::Sequential
            }
        };
        Self {
            patterns,
            replacements,
            secrets: secret_count,
            matcher: Some(matcher),
        }
    }

    /// A redactor with no secrets; `redact` always returns the input unchanged.
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            replacements: Vec::new(),
            secrets: 0,
            matcher: None,
        }
    }

    /// Number of distinct secrets held, not counting the per-line patterns.
    pub fn len(&self) -> usize {
        self.secrets
    }

    pub fn is_empty(&self) -> bool {
        self.secrets == 0
    }

    /// Returns the masked text and whether anything was replaced.
    pub fn redact<'a>(&self, s: &'a str) -> (Cow<'a, str>, bool) {
        match self.redact_bytes(s.as_bytes()) {
            None => (Cow::Borrowed(s), false),
            // Patterns and replacements are UTF-8, so matches end on char boundaries.
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(out) => (Cow::Owned(out), true),
                Err(e) => (
                    Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
                    true,
                ),
            },
        }
    }

    /// Masked copy of `hay`, or `None` when nothing matched.
    pub fn redact_bytes(&self, hay: &[u8]) -> Option<Vec<u8>> {
        match &self.matcher {
            None => None,
            Some(Matcher::Automaton(ac)) => {
                let mut out: Option<Vec<u8>> = None;
                let mut last = 0;
                for m in ac.find_iter(hay) {
                    let buf = out.get_or_insert_with(|| Vec::with_capacity(hay.len()));
                    buf.extend_from_slice(&hay[last..m.start()]);
                    buf.extend_from_slice(self.replacements[m.pattern().as_usize()].as_bytes());
                    last = m.end();
                }
                out.map(|mut buf| {
                    buf.extend_from_slice(&hay[last..]);
                    buf
                })
            }
            Some(Matcher::Sequential) => {
                let mut cur: Option<Vec<u8>> = None;
                for (pat, rep) in self.patterns.iter().zip(&self.replacements) {
                    let src = cur.as_deref().unwrap_or(hay);
                    if let Some(next) = replace_all(src, pat.as_bytes(), rep.as_bytes()) {
                        cur = Some(next);
                    }
                }
                cur
            }
        }
    }
}

fn replace_all(hay: &[u8], needle: &[u8], rep: &[u8]) -> Option<Vec<u8>> {
    let mut out: Option<Vec<u8>> = None;
    let mut last = 0;
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            let buf = out.get_or_insert_with(|| Vec::with_capacity(hay.len()));
            buf.extend_from_slice(&hay[last..i]);
            buf.extend_from_slice(rep);
            i += needle.len();
            last = i;
        } else {
            i += 1;
        }
    }
    out.map(|mut buf| {
        buf.extend_from_slice(&hay[last..]);
        buf
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn r(pairs: &[(&str, &str)]) -> Redactor {
        let v: Vec<(String, String)> = pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        Redactor::new(&v)
    }

    #[test]
    fn replaces_all_occurrences() {
        let red = r(&[("s3cr3tvalue", "aws-key")]);
        let (out, hit) = red.redact("a s3cr3tvalue b s3cr3tvalue c");
        assert!(hit);
        assert_eq!(out, "a [REDACTED:aws-key] b [REDACTED:aws-key] c");
    }

    #[test]
    fn noop_returns_borrowed() {
        let red = r(&[("s3cr3tvalue", "k")]);
        let (out, hit) = red.redact("nothing to see");
        assert!(!hit);
        assert!(matches!(out, Cow::Borrowed(_)));
        let (out, hit) = Redactor::empty().redact("anything");
        assert!(!hit && matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn leftmost_longest_wins_on_overlap() {
        let red = r(&[("abcdef", "short"), ("abcdefghij", "long")]);
        let (out, _) = red.redact("x abcdefghij y");
        assert_eq!(out, "x [REDACTED:long] y");
        let red = r(&[("abcdef", "one"), ("defghi", "two")]);
        let (out, _) = red.redact("abcdefghi");
        assert_eq!(out, "[REDACTED:one]ghi");
    }

    #[test]
    fn secret_at_start_and_end() {
        let red = r(&[("topsecret", "t")]);
        let (out, hit) = red.redact("topsecret");
        assert!(hit);
        assert_eq!(out, "[REDACTED:t]");
        let (out, _) = red.redact("topsecret mid topsecret");
        assert_eq!(out, "[REDACTED:t] mid [REDACTED:t]");
    }

    #[test]
    fn utf8_neighbours_are_preserved() {
        let red = r(&[("pässwörd1", "pw"), ("tokenvalue", "tok")]);
        let (out, hit) = red.redact("é日本pässwörd1🙂tokenvalue→x");
        assert!(hit);
        assert_eq!(out, "é日本[REDACTED:pw]🙂[REDACTED:tok]→x");
    }

    #[test]
    fn short_secrets_are_ignored() {
        let red = r(&[("abcde", "short"), ("abcdef", "ok")]);
        assert_eq!(red.len(), 1);
        let (out, _) = red.redact("abcde abcdef");
        assert_eq!(out, "abcde [REDACTED:ok]");
        assert!(r(&[("abc", "x")]).is_empty());
    }

    #[test]
    fn duplicate_secrets_keep_first_rule() {
        let red = r(&[("duplicate1", "a"), ("duplicate1", "b")]);
        assert_eq!(red.len(), 1);
        assert_eq!(red.redact("duplicate1").0, "[REDACTED:a]");
    }

    fn pem() -> String {
        let label = ["OPENSSH", "PRIVATE", "KEY"].join(" ");
        [
            format!("-----BEGIN {label}-----"),
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ".into(),
            "QyNTUxOQAAACDfakefakefakefakefakefakefake".into(),
            format!("-----END {label}-----"),
        ]
        .join("\n")
    }

    #[test]
    fn multi_line_secret_masks_block_and_each_line() {
        let red = r(&[(&pem(), "private-key")]);
        assert_eq!(red.len(), 1);
        let text = format!("key: |\n{}\nnext: 1\n", pem());
        let (out, hit) = red.redact(&text);
        assert!(hit);
        assert_eq!(
            out,
            "key: |\n[REDACTED:private-key]\n[REDACTED:private-key]\n[REDACTED:private-key]\n[REDACTED:private-key]\nnext: 1\n"
        );
        assert_eq!(out.lines().count(), text.lines().count());
        let (line, hit) = red.redact("  QyNTUxOQAAACDfakefakefakefakefakefakefake  ");
        assert!(hit);
        assert_eq!(line, "  [REDACTED:private-key]  ");
        let armor_line = pem().lines().next().unwrap().to_owned();
        let (armor, hit) = red.redact(&armor_line);
        assert!(!hit, "{armor}");
    }

    #[test]
    fn multi_line_secret_with_crlf_keeps_line_breaks() {
        let secret = "first-line-secret\r\nsecond-line-secret";
        let red = r(&[(secret, "k")]);
        let text = format!("a\r\n{secret}\r\nb");
        let (out, _) = red.redact(&text);
        assert_eq!(out, "a\r\n[REDACTED:k]\r\n[REDACTED:k]\r\nb");
        let lines: Vec<&str> = secret_lines(secret).collect();
        assert_eq!(lines, ["first-line-secret", "second-line-secret"]);
        assert_eq!(secret_lines("single-line-secret").count(), 0);
        assert_eq!(secret_lines("a\nshort\n-----END X KEY-----").count(), 0);
    }

    #[test]
    fn bytes_are_redacted_even_when_not_utf8() {
        let red = r(&[("s3cr3tvalue", "k")]);
        let hay = b"\xff\xfe s3cr3tvalue \x80";
        let out = red.redact_bytes(hay).unwrap();
        assert_eq!(out, b"\xff\xfe [REDACTED:k] \x80");
        assert!(red.redact_bytes(b"clean").is_none());
        assert!(Redactor::empty().redact_bytes(b"s3cr3tvalue").is_none());
    }

    #[test]
    fn sequential_replace_all_matches_automaton() {
        assert_eq!(
            replace_all(b"xabcabcx", b"abc", b"[R]").unwrap(),
            b"x[R][R]x"
        );
        assert!(replace_all(b"short", b"longer-needle", b"r").is_none());
    }
}
