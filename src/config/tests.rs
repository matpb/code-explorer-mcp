use std::path::{Path, PathBuf};

use super::*;

struct Fx {
    dir: tempfile::TempDir,
    secret: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "not-a-real-token\n").expect("write secret");
        Fx { dir, secret }
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn head(&self) -> String {
        format!(
            "version = 1\n[server]\ndata_dir = {:?}\n[auth]\n[credentials.c]\ntype = \"https_token\"\nusername = \"u\"\nsecret_file = {:?}\n",
            self.data(),
            self.secret
        )
    }

    fn repo(&self, extra: &str) -> String {
        format!(
            "[[repo]]\nid = \"a\"\nhost = \"github\"\npath = \"example-org/a\"\nbranch = \"main\"\ndescription = \"d\"\ncredential = \"c\"\n{extra}"
        )
    }

    fn valid(&self) -> String {
        format!("{}{}", self.head(), self.repo(""))
    }
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn load(text: &str) -> Result<Loaded, Problems> {
    Config::from_str_with_env(text, Path::new("config.toml"), &no_env)
}

fn load_env(text: &str, vars: &'static [(&str, &str)]) -> Result<Loaded, Problems> {
    let env = move |n: &str| {
        vars.iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.to_string())
    };
    Config::from_str_with_env(text, Path::new("config.toml"), &env)
}

fn errs(r: Result<Loaded, Problems>) -> Vec<Problem> {
    let all = r.expect_err("expected problems").0;
    assert!(all.iter().any(|p| p.fatal));
    all.into_iter().filter(|p| p.fatal).collect()
}

fn line_in(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .expect("needle")
        + 1
}

fn example_text(fx: &Fx) -> String {
    let key = fx.dir.path().join("api_key");
    let known = fx.dir.path().join("known_hosts");
    std::fs::write(&key, "not-a-real-key\n").expect("write key");
    std::fs::write(&known, "example.com ssh-ed25519 AAAA\n").expect("write known_hosts");
    let mut text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml"))
            .expect("example config");
    for (from, to) in [
        ("/data", fx.data()),
        ("/run/secrets/web_ui_key", fx.secret.clone()),
        ("/run/secrets/api_key", key),
        ("/etc/code-explorer/known_hosts", known),
    ] {
        text = text.replace(
            &format!("\"{from}\""),
            &format!("{:?}", to.display().to_string()),
        );
    }
    text
}

#[test]
fn minimal_config_loads_with_defaults() {
    let fx = Fx::new();
    let loaded = load(&fx.valid()).expect("valid");
    assert!(loaded.warnings.is_empty());
    let c = loaded.config;
    assert_eq!(c.limits, Limits::default());
    assert_eq!(c.pull.interval, Duration::from_secs(300));
    assert_eq!(c.scan.policy, ScanPolicy::Redact);
    assert_eq!(
        c.server.client_ip_header.as_deref(),
        Some("X-Forwarded-For")
    );
    assert_eq!(c.repo("a").map(|r| r.branch.as_str()), Some("main"));
    assert!(c.repo("zzz").is_none());
}

#[test]
fn example_config_loads() {
    let fx = Fx::new();
    let text = example_text(&fx);
    let loaded =
        load_env(&text, &[("DESIGN_SYSTEM_TOKEN", "not-a-real-token")]).expect("example loads");
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    let c = &loaded.config;
    assert_eq!(c.repo.len(), 4);
    assert_eq!(c.credentials.len(), 3);
    let api = c.repo("api").expect("api");
    assert_eq!(
        api.pull_interval_or(c.pull.interval),
        Duration::from_secs(120)
    );
    let ds = c.repo("design-system").expect("ds");
    assert_eq!(ds.scan_policy_or(c.scan.policy), ScanPolicy::Block);
    assert!(c.credential_for(ds).is_some_and(|c| !c.is_ssh()));
    assert!(
        c.credential_for(c.repo("api").expect("api"))
            .is_some_and(Credential::is_ssh)
    );
    assert!(
        c.credential_for(c.repo("api-next").expect("api-next"))
            .is_some_and(Credential::is_ssh)
    );
    assert_eq!(c.scan.allowlist, vec!["a1b2c3d4e5f6".to_string()]);
}

#[test]
fn example_config_reports_missing_env_var() {
    let fx = Fx::new();
    let text = example_text(&fx);
    let p = errs(load(&text));
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].key, "credentials.design-system-token.env");
    assert_eq!(
        p[0].line,
        Some(line_in(&text, "env      = \"DESIGN_SYSTEM_TOKEN\""))
    );
}

#[test]
fn unknown_field_reported_with_line() {
    let fx = Fx::new();
    let text = fx.valid() + "brnach = \"x\"\n";
    let p = errs(load(&text));
    assert_eq!(p.len(), 1);
    assert!(p[0].fatal);
    assert_eq!(p[0].key, "repo[0].brnach");
    assert!(p[0].message.contains("unknown field"));
    assert_eq!(p[0].line, Some(line_in(&text, "brnach")));
    let shown = p[0].to_string();
    assert!(
        shown.starts_with(&format!(
            "config.toml:{}: repo[0].brnach: ",
            line_in(&text, "brnach")
        )),
        "{shown}"
    );
    assert!(
        shown.ends_with("(remove the field or correct its spelling)"),
        "{shown}"
    );
}

#[test]
fn syntax_error_has_line() {
    let fx = Fx::new();
    let text = fx.head() + "[[repo]]\nid = \n";
    let p = errs(load(&text));
    assert_eq!(p.len(), 1);
    assert!(p[0].line.is_some());
}

#[test]
fn bad_duration_string_is_fatal() {
    let fx = Fx::new();
    let text = fx.valid().replace(
        "[auth]\n",
        "[auth]\n[auth.failed_attempts]\nwindow = \"soon\"\n",
    );
    let p = errs(load(&text));
    assert!(p[0].message.contains("invalid duration"), "{}", p[0]);
    assert_eq!(p[0].line, Some(line_in(&text, "window")));
}

#[test]
fn duplicate_repo_id() {
    let fx = Fx::new();
    let text = format!(
        "{}{}{}",
        fx.head(),
        fx.repo(""),
        fx.repo("").replace("\"main\"", "\"dev\"")
    );
    let p = errs(load(&text));
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].key, "repo[1].id");
    assert!(p[0].message.contains("duplicate"));
    assert_eq!(
        p[0].line,
        Some(
            text.lines()
                .enumerate()
                .filter(|(_, l)| l.starts_with("id = "))
                .nth(1)
                .map(|(i, _)| i + 1)
                .expect("line")
        )
    );
}

#[test]
fn bad_repo_ids() {
    let fx = Fx::new();
    for bad in ["Upper", "-lead", "has space", "", "a/b"] {
        let text = fx.valid().replace("id = \"a\"", &format!("id = {bad:?}"));
        let p = errs(load(&text));
        assert_eq!(p[0].key, "repo[0].id", "{bad:?}");
    }
}

#[test]
fn bad_branch_name() {
    let fx = Fx::new();
    for bad in [
        "-x",
        "a..b",
        "a b",
        "a~b",
        "a^b",
        "a:b",
        "a?b",
        "a*b",
        "a[b",
        "a\\b",
        "main/",
        "x.lock",
        "a@{b",
        "@",
        ".hidden",
        "a/.b",
        "a//b",
        "a.",
        "a\tb",
        "feature/x.lock/y",
        "",
    ] {
        let text = fx
            .valid()
            .replace("branch = \"main\"", &format!("branch = {bad:?}"));
        let p = errs(load(&text));
        assert_eq!(p.len(), 1, "{bad:?}: {p:?}");
        assert_eq!(p[0].key, "repo[0].branch", "{bad:?}");
        assert_eq!(p[0].line, Some(line_in(&text, "branch =")), "{bad:?}");
    }
    for good in ["main", "release/1.2", "feature/a-b_c", "v1.0.0", "a@b"] {
        assert!(is_valid_branch(good).is_ok(), "{good}");
    }
}

#[test]
fn bad_repo_paths() {
    let fx = Fx::new();
    for bad in [
        "onlyone", "a/b/c", "a/", "/b", "a b/c", "../x", "a/..", "-a/b", "a/b;c",
    ] {
        let text = fx.valid().replace("example-org/a", bad);
        let p = errs(load(&text));
        assert_eq!(p[0].key, "repo[0].path", "{bad:?}");
    }
}

#[test]
fn missing_credential_reference() {
    let fx = Fx::new();
    let text = fx
        .valid()
        .replace("credential = \"c\"", "credential = \"nope\"");
    let p = errs(load(&text));
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].key, "repo[0].credential");
    assert!(p[0].message.contains("nope"));
    assert_eq!(p[0].line, Some(line_in(&text, "credential = \"nope\"")));
}

#[test]
fn env_var_unset_or_empty() {
    let fx = Fx::new();
    let text = fx.valid().replace(
        &format!("secret_file = {:?}\n", fx.secret),
        "env = \"MY_TOKEN_VAR\"\n",
    );
    let p = errs(load(&text));
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].key, "credentials.c.env");
    assert_eq!(p[0].line, Some(line_in(&text, "env =")));
    assert!(errs(load_env(&text, &[("MY_TOKEN_VAR", "  ")])).len() == 1);
    assert!(load_env(&text, &[("MY_TOKEN_VAR", "x")]).is_ok());
}

#[test]
fn secret_file_missing_or_empty() {
    let fx = Fx::new();
    std::fs::remove_file(&fx.secret).expect("rm");
    let text = fx.valid();
    let p = errs(load(&text));
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(p[0].key, "credentials.c.secret_file");
    assert_eq!(p[0].line, Some(line_in(&text, "secret_file")));
    std::fs::write(&fx.secret, "\n").expect("write");
    assert!(errs(load(&text))[0].message.contains("empty"));
}

#[test]
fn secret_file_and_env_are_exclusive() {
    let fx = Fx::new();
    let both = fx
        .valid()
        .replace("secret_file", "env = \"V\"\nsecret_file");
    assert!(
        errs(load_env(&both, &[("V", "x")]))[0]
            .message
            .contains("exactly one")
    );
    let neither = fx
        .valid()
        .replace(&format!("secret_file = {:?}\n", fx.secret), "");
    assert!(errs(load(&neither))[0].message.contains("either"));
}

#[test]
fn interval_under_30s() {
    let fx = Fx::new();
    let global = fx
        .valid()
        .replace("[auth]\n", "[auth]\n[pull]\ninterval = \"10s\"\n");
    let p = errs(load(&global));
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].key, "pull.interval");
    let per_repo = format!("{}{}", fx.head(), fx.repo("pull_interval = \"29s\"\n"));
    let p = errs(load(&per_repo));
    assert_eq!(p[0].key, "repo[0].pull_interval");
    assert_eq!(p[0].line, Some(line_in(&per_repo, "pull_interval")));
    let ok = format!("{}{}", fx.head(), fx.repo("pull_interval = \"30s\"\n"));
    assert!(load(&ok).is_ok());
}

#[test]
fn collects_all_problems_in_one_run() {
    let fx = Fx::new();
    let text = fx
        .valid()
        .replace("branch = \"main\"", "branch = \"bad branch\"")
        .replace("credential = \"c\"", "credential = \"missing\"")
        .replace("[auth]\n", "[auth]\n[pull]\ninterval = \"1s\"\n");
    let p = errs(load(&text));
    let keys: Vec<&str> = p.iter().map(|x| x.key.as_str()).collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    for k in ["pull.interval", "repo[0].branch", "repo[0].credential"] {
        assert!(keys.contains(&k), "{k} in {keys:?}");
    }
    let shown = Problems(p).to_string();
    assert_eq!(shown.lines().count(), 3);
}

#[test]
fn duplicate_host_path_branch_warns() {
    let fx = Fx::new();
    let second = fx.repo("").replace("id = \"a\"", "id = \"b\"");
    let text = format!("{}{}{}", fx.head(), fx.repo(""), second);
    let loaded = load(&text).expect("warnings only");
    assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    let w = &loaded.warnings[0];
    assert!(!w.fatal);
    assert_eq!(w.key, "repo[1].branch");
    assert!(w.message.contains("repo[0]"));
}

#[test]
fn other_warnings() {
    let fx = Fx::new();
    let text = fx.valid().replace("description = \"d\"\n", "").replace(
        "[server]\n",
        "[server]\ntrusted_proxies = []\nclient_ip_header = \"X-Forwarded-For\"\n",
    );
    let loaded = load(&text).expect("warnings only");
    let keys: Vec<&str> = loaded.warnings.iter().map(|w| w.key.as_str()).collect();
    assert!(keys.contains(&"server.trusted_proxies"), "{keys:?}");
    assert!(keys.contains(&"repo[0].description"), "{keys:?}");
    let cleared = fx.valid().replace(
        "[server]\n",
        "[server]\ntrusted_proxies = []\nclient_ip_header = \"\"\n",
    );
    let loaded = load(&cleared).expect("ok");
    assert_eq!(loaded.config.server.client_ip_header, None);
    assert!(
        !loaded
            .warnings
            .iter()
            .any(|w| w.key == "server.trusted_proxies")
    );
}

#[test]
fn default_config_has_no_trusted_proxy_and_no_warning() {
    let fx = Fx::new();
    let loaded = load(&fx.valid()).expect("valid");
    assert!(loaded.config.server.trusted_proxies.is_empty());
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn trusted_proxies_without_a_header_warns() {
    let fx = Fx::new();
    let text = fx.valid().replace(
        "[server]\n",
        "[server]\ntrusted_proxies = [\"172.30.0.2/32\"]\nclient_ip_header = \"\"\n",
    );
    let loaded = load(&text).expect("warnings only");
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.key == "server.client_ip_header" && !w.fatal),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn connection_and_verification_limits_are_validated() {
    let fx = Fx::new();
    let text = fx
        .valid()
        .replace("[server]\n", "[server]\nmax_connections = 8\n");
    let p = errs(load(&text));
    assert_eq!(p[0].key, "server.max_connections");
    let text = fx
        .valid()
        .replace("[auth]\n", "[auth]\nmax_concurrent_verifications = 0\n");
    let p = errs(load(&text));
    assert_eq!(p[0].key, "auth.max_concurrent_verifications");
    let loaded = load(&fx.valid()).expect("defaults");
    assert_eq!(loaded.config.server.max_connections, 1024);
    assert_eq!(loaded.config.auth.max_concurrent_verifications, 4);
}

#[test]
fn type_errors_in_different_sections_are_all_reported() {
    let fx = Fx::new();
    let text = fx
        .valid()
        .replace(
            "[server]\n",
            "[server]\ntrusted_proxies = [\"10.0.0.0/99\"]\n",
        )
        .replace(
            "[auth]\n",
            "[auth]\n[auth.failed_attempts]\nwindow = \"soon\"\n",
        )
        + "brnach = \"x\"\n";
    let p = errs(load(&text));
    assert!(p.len() >= 3, "{p:?}");
    let by_key = |k: &str| {
        p.iter()
            .find(|x| x.key == k)
            .unwrap_or_else(|| panic!("{k} in {p:?}"))
    };
    let cidr = by_key("server.trusted_proxies");
    assert!(cidr.message.contains("invalid CIDR"), "{}", cidr.message);
    assert_eq!(cidr.line, Some(line_in(&text, "trusted_proxies")));
    let dur = by_key("auth.failed_attempts.window");
    assert!(dur.message.contains("invalid duration"), "{}", dur.message);
    assert_eq!(dur.line, Some(line_in(&text, "window")));
    let typo = by_key("repo[0].brnach");
    assert_eq!(typo.line, Some(line_in(&text, "brnach")));
}

#[test]
fn bad_repo_and_credential_entries_each_get_a_problem() {
    let fx = Fx::new();
    let text = format!(
        "{}[credentials.d]\ntype = \"nope\"\n{}{}",
        fx.head(),
        fx.repo("pull_interval = \"whenever\"\n"),
        fx.repo("")
            .replace("id = \"a\"", "id = \"b\"")
            .replace("host = \"github\"", "host = \"gitlab\"")
    );
    let p = errs(load(&text));
    let keys: Vec<&str> = p.iter().map(|x| x.key.as_str()).collect();
    for k in ["credentials.d", "repo[0].pull_interval", "repo[1].host"] {
        assert!(keys.contains(&k), "{k} in {keys:?}");
    }
}

#[test]
fn missing_required_sections_are_listed_together() {
    let p = errs(load("version = 1\n"));
    let keys: Vec<&str> = p.iter().map(|x| x.key.as_str()).collect();
    for k in ["server", "auth", "repo"] {
        assert!(keys.contains(&k), "{k} in {keys:?}");
    }
}

#[test]
fn remote_url_forms() {
    let fx = Fx::new();
    let loaded = load(&fx.valid()).expect("valid");
    let cfg = loaded.config;
    let https = Credential::HttpsToken {
        username: "u".into(),
        secret_file: None,
        env: Some("V".into()),
        expires: None,
    };
    let ssh = Credential::SshKey {
        secret_file: PathBuf::from("/k"),
        expires: None,
    };
    let mut gh = cfg.repo[0].clone();
    assert_eq!(
        gh.remote_url(Some(&https)),
        "https://github.com/example-org/a.git"
    );
    assert_eq!(
        gh.remote_url(Some(&ssh)),
        "git@github.com:example-org/a.git"
    );
    gh.host = Host::Bitbucket;
    gh.path = "example-workspace/api".into();
    assert_eq!(
        gh.remote_url(Some(&https)),
        "https://bitbucket.org/example-workspace/api.git"
    );
    assert_eq!(
        gh.remote_url(Some(&ssh)),
        "git@ssh.bitbucket.org:example-workspace/api.git"
    );
    gh.remote_url_override = Some("/tmp/bare.git".into());
    assert_eq!(gh.remote_url(Some(&https)), "/tmp/bare.git");
    assert_eq!(gh.remote_url(Some(&ssh)), "/tmp/bare.git");
}

#[test]
fn remote_url_override_needs_env_flag() {
    let fx = Fx::new();
    let text = format!(
        "{}{}",
        fx.head(),
        fx.repo("remote_url_override = \"/tmp/bare.git\"\n")
    );
    let p = errs(load(&text));
    assert_eq!(p[0].key, "repo[0].remote_url_override");
    let ok = load_env(&text, &[(ALLOW_LOCAL_REMOTES_ENV, "1")]).expect("allowed");
    assert_eq!(
        ok.config.repo[0].remote_url_override.as_deref(),
        Some("/tmp/bare.git")
    );
}

#[test]
fn expired_credential_is_fatal() {
    let fx = Fx::new();
    let text = fx.valid().replace(
        "username = \"u\"\n",
        "username = \"u\"\nexpires = \"2000-01-01\"\n",
    );
    let p = errs(load(&text));
    assert_eq!(p[0].key, "credentials.c.expires");
    assert_eq!(p[0].line, Some(line_in(&text, "expires")));
}

#[test]
fn misc_field_validation() {
    let fx = Fx::new();
    let cases: &[(&str, &str, &str)] = &[
        ("version = 1", "version = 2", "version"),
        (
            "[server]\n",
            "[server]\nlisten = \"0.0.0.0:9090\"\n",
            "server.admin_listen",
        ),
        (
            "[server]\n",
            "[server]\npublic_url = \"ftp://x\"\n",
            "server.public_url",
        ),
        (
            "[server]\n",
            "[server]\nallowed_origins = [\"app.example.com\"]\n",
            "server.allowed_origins",
        ),
        (
            "[server]\n",
            "[server]\nallowed_origins = [\"https://app.example.com/\"]\n",
            "server.allowed_origins",
        ),
        (
            "[server]\n",
            "[server]\nclient_ip_header = \"bad header\"\n",
            "server.client_ip_header",
        ),
        (
            "[auth]\n",
            "[auth]\n[limits]\nmax_line_chars = 79\n",
            "limits.max_line_chars",
        ),
        (
            "[auth]\n",
            "[auth]\n[limits]\nmax_response_bytes = 4095\n",
            "limits.max_response_bytes",
        ),
        (
            "[auth]\n",
            "[auth]\n[limits]\nrg_timeout = \"0s\"\n",
            "limits.rg_timeout",
        ),
        (
            "[auth]\n",
            "[auth]\n[limits]\nmax_concurrent_workers = 0\n",
            "limits.max_concurrent_workers",
        ),
        (
            "[auth]\n",
            "[auth]\n[scan]\nengine = \"trufflehog\"\n",
            "scan.engine",
        ),
        (
            "[auth]\n",
            "[auth]\n[deny]\npaths = [\"[abc\"]\n",
            "deny.paths",
        ),
        (
            "[auth]\n",
            "[auth]\n[auth.failed_attempts]\nipv6_prefix = 0\n",
            "auth.failed_attempts.ipv6_prefix",
        ),
    ];
    for (from, to, key) in cases {
        let text = fx.valid().replacen(from, to, 1);
        let p = errs(load(&text));
        assert!(
            p.iter().any(|x| x.key == *key && x.line.is_some()),
            "{key}: {p:?}"
        );
    }
}

#[test]
fn invalid_cidr_and_listen_are_fatal() {
    let fx = Fx::new();
    for line in ["trusted_proxies = [\"10.0.0.0/99\"]", "listen = \"nope\""] {
        let text = fx
            .valid()
            .replacen("[server]\n", &format!("[server]\n{line}\n"), 1);
        let p = errs(load(&text));
        assert!(p[0].line.is_some(), "{line}: {p:?}");
    }
}

#[test]
fn ssh_credential_needs_known_hosts() {
    let fx = Fx::new();
    let text = format!(
        "{}[credentials.k]\ntype = \"ssh_key\"\nsecret_file = {:?}\n{}",
        fx.head(),
        fx.secret,
        fx.repo("")
    );
    let p = errs(load(&text));
    assert!(p.iter().any(|x| x.key == "pull.known_hosts_file"), "{p:?}");
}

#[test]
fn data_dir_is_created_and_blocked_path_is_reported() {
    let fx = Fx::new();
    assert!(load(&fx.valid()).is_ok());
    assert!(fx.data().is_dir());
    let blocker = fx.dir.path().join("file");
    std::fs::write(&blocker, "x").expect("write");
    let text = fx.valid().replace(
        &format!("{:?}", fx.data()),
        &format!("{:?}", blocker.join("sub")),
    );
    let p = errs(load(&text));
    assert_eq!(p[0].key, "server.data_dir");
}

#[test]
fn load_reads_a_file_and_reports_a_missing_one() {
    let fx = Fx::new();
    let path = fx.dir.path().join("config.toml");
    std::fs::write(&path, fx.valid()).expect("write");
    let loaded = Config::load(&path).expect("loads");
    assert_eq!(loaded.config.source, path);
    let p = Config::load(&fx.dir.path().join("absent.toml")).expect_err("err");
    assert_eq!(p.len(), 1);
}

#[test]
fn line_of_walks_nested_keys() {
    let text = "version = 1\n[a]\nx = 1\n[[repo]]\nid = \"p\"\n[[repo]]\nid = \"q\"\nbranch = \"b\"\n[credentials.web]\nenv = \"E\"\n";
    let doc = toml_edit::Document::parse(text).expect("doc");
    assert_eq!(line_of(&doc, text, "version"), Some(1));
    assert_eq!(line_of(&doc, text, "repo[1].branch"), Some(8));
    assert_eq!(line_of(&doc, text, "repo[1].id"), Some(7));
    assert_eq!(line_of(&doc, text, "repo[1].missing"), Some(6));
    assert_eq!(line_of(&doc, text, "credentials.web.env"), Some(10));
    assert_eq!(line_of(&doc, text, "nothing.here"), None);
}

#[test]
fn problem_display_omits_missing_line() {
    let p = Problem {
        file: PathBuf::from("c.toml"),
        line: None,
        key: "k".into(),
        message: "m".into(),
        fix: "f".into(),
        fatal: true,
    };
    assert_eq!(p.to_string(), "c.toml: k: m (f)");
    assert_eq!(
        Problem { line: Some(3), ..p }.to_string(),
        "c.toml:3: k: m (f)"
    );
}

#[test]
fn binaries_check_reports_missing_and_accepts_present() {
    let fx = Fx::new();
    let text = fx
        .valid()
        .replace("[server]\n", "[server]\ngit_path = \"/nonexistent/git\"\n");
    let cfg = load(&text).expect("valid").config;
    let p = cfg.validate_binaries();
    assert!(
        p.iter().any(|x| x.key == "server.git_path" && x.fatal),
        "{p:?}"
    );
    let cfg = load(&fx.valid()).expect("valid").config;
    let p = cfg.validate_binaries();
    for x in &p {
        assert!(!x.message.contains("need at least"), "{x}");
    }
}

#[test]
fn repo_without_credential_is_anonymous_with_warning() {
    let fx = Fx::new();
    let text = format!(
        "{}{}",
        fx.head(),
        fx.repo("").replace("credential = \"c\"\n", "")
    );
    let loaded = load(&text).expect("anonymous repo loads");
    let cfg = &loaded.config;
    let repo = cfg.repo("a").expect("repo a");
    assert!(repo.credential.is_none());
    assert!(cfg.credential_for(repo).is_none());
    assert_eq!(
        repo.remote_url(None),
        "https://github.com/example-org/a.git"
    );
    let w = loaded
        .warnings
        .iter()
        .find(|w| w.key == "repo[0].credential")
        .expect("no-credential warning");
    assert!(
        w.message
            .contains("only public repos can be read anonymously")
    );
}
