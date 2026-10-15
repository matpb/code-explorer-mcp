//! Masks exact secret values found by the scanner in outgoing strings.

use aho_corasick::{AhoCorasick, MatchKind};
use std::borrow::Cow;
use std::collections::HashSet;

const MIN_SECRET_LEN: usize = 6;

#[derive(Debug)]
enum Matcher {
    Automaton(AhoCorasick),
    /// Fallback if the automaton cannot be built: longest secrets replaced first.
    Sequential,
}

/// Replaces known secret values with `[REDACTED:<rule_id>]`.
#[derive(Debug)]
pub struct Redactor {
    secrets: Vec<String>,
    replacements: Vec<String>,
    matcher: Option<Matcher>,
}

impl Redactor {
    /// Builds a redactor from `(secret, rule_id)` pairs; secrets under 6 bytes are ignored.
    pub fn new(findings: &[(String, String)]) -> Self {
        let mut seen = HashSet::new();
        let mut secrets = Vec::new();
        let mut replacements = Vec::new();
        for (secret, rule_id) in findings {
            if secret.len() < MIN_SECRET_LEN || !seen.insert(secret.as_str()) {
                continue;
            }
            secrets.push(secret.clone());
            replacements.push(format!("[REDACTED:{rule_id}]"));
        }
        if secrets.is_empty() {
            return Self::empty();
        }
        let matcher = match AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&secrets)
        {
            Ok(ac) => Matcher::Automaton(ac),
            Err(err) => {
                tracing::error!(error = %err, "redaction automaton build failed, using sequential fallback");
                let mut order: Vec<usize> = (0..secrets.len()).collect();
                order.sort_by_key(|&i| std::cmp::Reverse(secrets[i].len()));
                secrets = order.iter().map(|&i| secrets[i].clone()).collect();
                replacements = order.iter().map(|&i| replacements[i].clone()).collect();
                Matcher::Sequential
            }
        };
        Self {
            secrets,
            replacements,
            matcher: Some(matcher),
        }
    }

    /// A redactor with no secrets; `redact` always returns the input unchanged.
    pub fn empty() -> Self {
        Self {
            secrets: Vec::new(),
            replacements: Vec::new(),
            matcher: None,
        }
    }

    /// Number of distinct secrets held.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Returns the masked text and whether anything was replaced.
    pub fn redact<'a>(&self, s: &'a str) -> (Cow<'a, str>, bool) {
        match &self.matcher {
            None => (Cow::Borrowed(s), false),
            Some(Matcher::Automaton(ac)) => {
                let mut out: Option<String> = None;
                let mut last = 0;
                for m in ac.find_iter(s) {
                    let buf = out.get_or_insert_with(|| String::with_capacity(s.len()));
                    buf.push_str(&s[last..m.start()]);
                    buf.push_str(&self.replacements[m.pattern().as_usize()]);
                    last = m.end();
                }
                match out {
                    Some(mut buf) => {
                        buf.push_str(&s[last..]);
                        (Cow::Owned(buf), true)
                    }
                    None => (Cow::Borrowed(s), false),
                }
            }
            Some(Matcher::Sequential) => {
                let mut cur = Cow::Borrowed(s);
                let mut changed = false;
                for (secret, rep) in self.secrets.iter().zip(&self.replacements) {
                    if cur.contains(secret.as_str()) {
                        cur = Cow::Owned(cur.replace(secret.as_str(), rep));
                        changed = true;
                    }
                }
                (cur, changed)
            }
        }
    }
}

#[cfg(test)]
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
}
