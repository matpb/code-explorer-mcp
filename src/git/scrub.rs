//! Masks credentials and token-shaped strings in git output before it is logged or returned.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

static USERINFO: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"://[^/\s@:]+:[^/\s@]*@").ok());

static TOKENS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"|github_pat_[A-Za-z0-9_]{20,}",
        r"|ATB[A-Za-z0-9_-]{20,}",
        r"|ATC[A-Za-z0-9_-]{20,}",
        r"|ATATT[A-Za-z0-9_-]{20,}",
        r"|cex_[a-z2-7]{8}_[A-Za-z0-9_-]{43}",
        r"|[A-Za-z0-9+/_=-]{40,}",
    ))
    .ok()
});

/// Replaces `://user:pass@` with `://***@` and token-shaped runs with `***`.
pub fn scrub_stderr(input: &str) -> String {
    let after_userinfo: Cow<str> = match USERINFO.as_ref() {
        Some(re) => re.replace_all(input, "://***@"),
        None => Cow::Borrowed(input),
    };
    match TOKENS.as_ref() {
        Some(re) => re.replace_all(&after_userinfo, "***").into_owned(),
        None => after_userinfo.into_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn masks_userinfo() {
        let out = scrub_stderr("fatal: unable to access 'https://bob:hunter2@example.com/r.git/'");
        assert_eq!(
            out,
            "fatal: unable to access 'https://***@example.com/r.git/'"
        );
    }

    #[test]
    fn keeps_plain_urls_and_text() {
        let text = "fatal: repository 'https://example.com/a/b.git/' not found";
        assert_eq!(scrub_stderr(text), text);
    }

    #[test]
    fn masks_token_shapes() {
        let secret_a = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1");
        let secret_b = format!("github_pat_{}", "11ABCDEFG0abcdefghij_klmnop");
        let secret_c = format!("ATBB{}", "x".repeat(24));
        let secret_d = format!("ATCT{}", "y-_".repeat(8));
        let secret_e = format!("ATATT{}", "z".repeat(30));
        let secret_f = format!("cex_abcdefgh_{}", "Q".repeat(43));
        let secret_g = "a1B2c3D4e5F6g7H8i9J0".repeat(3);
        for secret in [
            secret_a, secret_b, secret_c, secret_d, secret_e, secret_f, secret_g,
        ] {
            let out = scrub_stderr(&format!("remote: token {secret} rejected"));
            assert_eq!(out, "remote: token *** rejected", "leaked {secret}");
        }
    }

    #[test]
    fn short_words_survive() {
        assert_eq!(
            scrub_stderr("ghp_short and ATBshort"),
            "ghp_short and ATBshort"
        );
    }
}
