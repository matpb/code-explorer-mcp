//! End-to-end tests of the `code-explorer` binary against local bare repos.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;

const BIN: &str = env!("CARGO_BIN_EXE_code-explorer");
const ALLOW_LOCAL: &str = "CODE_EXPLORER_ALLOW_LOCAL_REMOTES";

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Creates a bare repo with one commit holding `files` and returns its path.
fn bare_repo(root: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
    let work = root.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).expect("mkdir");
    git(&work, &["init", "-q", "-b", "main"]);
    for (path, content) in files {
        std::fs::write(work.join(path), content).expect("write file");
    }
    git(&work, &["add", "."]);
    git(&work, &["commit", "-q", "-m", "initial commit"]);
    let bare = root.join(format!("{name}.git"));
    git(
        root,
        &[
            "clone",
            "-q",
            "--bare",
            work.to_str().expect("utf8"),
            bare.to_str().expect("utf8"),
        ],
    );
    bare
}

struct Fx {
    dir: tempfile::TempDir,
    config: PathBuf,
    keys: PathBuf,
    listen: u16,
    admin: u16,
}

impl Fx {
    /// Writes a config whose single repo is served from `bare` through `remote_url_override`.
    fn point_at(&self, bare: &Path) {
        self.write_config(&format!(
            "remote_url_override = {:?}\n",
            format!("file://{}", bare.display())
        ));
    }

    fn empty() -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        let keys = dir.path().join("keys.toml");
        std::fs::write(&keys, "").expect("keys");
        Fx {
            dir,
            config,
            keys,
            listen: free_port(),
            admin: free_port(),
        }
    }

    fn write_config(&self, repo_extra: &str) {
        let text = format!(
            "version = 1\n[server]\nlisten = \"127.0.0.1:{}\"\nadmin_listen = \"127.0.0.1:{}\"\ndata_dir = {:?}\n[auth]\nkeys_file = {:?}\n[[repo]]\nid = \"demo\"\nhost = \"github\"\npath = \"example-org/demo\"\nbranch = \"main\"\ndescription = \"demo repo\"\n{repo_extra}",
            self.listen,
            self.admin,
            self.dir.path().join("data").display().to_string(),
            self.keys.display().to_string(),
        );
        std::fs::write(&self.config, text).expect("config");
    }

    fn cmd(&self) -> AssertCommand {
        let mut c = AssertCommand::new(BIN);
        c.arg("--config").arg(&self.config).env(ALLOW_LOCAL, "1");
        c
    }
}

#[test]
fn version_prints_the_crate_version() {
    AssertCommand::new(BIN)
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn askpass_is_hidden_from_help() {
    AssertCommand::new(BIN)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("check-config"))
        .stdout(predicate::str::contains("askpass").not());
}

#[test]
fn check_config_reports_a_typo_with_its_line() {
    let fx = Fx::empty();
    fx.write_config("");
    let text = std::fs::read_to_string(&fx.config)
        .expect("read")
        .replace("\nlisten = ", "\nlistn = ");
    std::fs::write(&fx.config, text).expect("write");
    fx.cmd()
        .arg("check-config")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "config.toml:3: listn: unknown field",
        ))
        .stdout(predicate::str::contains("config has 1 problems"));
}

#[test]
fn check_config_accepts_a_valid_config() {
    let fx = Fx::empty();
    let key = fx.dir.path().join("deploy_key");
    let known = fx.dir.path().join("known_hosts");
    std::fs::write(&key, "not-a-real-key\n").expect("key");
    std::fs::write(&known, "example.com ssh-ed25519 AAAA\n").expect("known_hosts");
    let text = format!(
        "version = 1\n[server]\ndata_dir = {:?}\n[auth]\nkeys_file = {:?}\n[pull]\nknown_hosts_file = {:?}\n[credentials.k]\ntype = \"ssh_key\"\nsecret_file = {:?}\n[[repo]]\nid = \"demo\"\nhost = \"github\"\npath = \"example-org/demo\"\nbranch = \"main\"\ndescription = \"demo repo\"\ncredential = \"k\"\n",
        fx.dir.path().join("data").display().to_string(),
        fx.keys.display().to_string(),
        known.display().to_string(),
        key.display().to_string(),
    );
    std::fs::write(&fx.config, text).expect("config");
    AssertCommand::new(BIN)
        .arg("--config")
        .arg(&fx.config)
        .arg("check-config")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "config ok: 1 repos, 1 credentials, 0 keys",
        ));
}

#[test]
fn check_config_probe_reaches_a_local_remote() {
    let fx = Fx::empty();
    let bare = bare_repo(fx.dir.path(), "demo", &[("README.md", "hello\n")]);
    fx.point_at(&bare);
    fx.cmd()
        .args(["check-config", "--probe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("repo demo: ok "))
        .stdout(predicate::str::contains(
            "config ok: 1 repos, 0 credentials, 0 keys",
        ));
}

#[test]
fn keygen_print_only_leaves_the_keys_file_alone() {
    let fx = Fx::empty();
    fx.write_config("");
    fx.cmd()
        .args(["keygen", "--name", "t", "--print-only"])
        .assert()
        .success()
        .stdout(predicate::str::contains("key: cex_"))
        .stdout(predicate::str::contains("[[key]]"))
        .stderr(predicate::str::contains("will not be shown again"));
    assert_eq!(std::fs::read_to_string(&fx.keys).expect("keys"), "");
}

#[test]
fn keygen_appends_and_the_config_still_checks() {
    let fx = Fx::empty();
    fx.write_config("");
    fx.cmd()
        .args([
            "keygen",
            "--name",
            "t",
            "--repos",
            "demo",
            "--expires",
            "2999-01-01",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("key: cex_"));
    let keys = std::fs::read_to_string(&fx.keys).expect("keys");
    assert!(
        keys.contains("[[key]]") && keys.contains("name = \"t\""),
        "{keys}"
    );
    assert!(!keys.contains("cex_"), "plaintext key must not be stored");
    fx.cmd()
        .arg("check-config")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 keys"));
    fx.cmd()
        .args(["keygen", "--name", "t"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"));
    fx.cmd()
        .args(["keygen", "--name", "u", "--repos", "nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown repo ids: nope"));
}

#[test]
fn healthcheck_fails_when_nothing_listens() {
    let fx = Fx::empty();
    fx.write_config("");
    fx.cmd().arg("healthcheck").assert().code(1);
    fx.cmd().arg("status").assert().code(1);
}

#[test]
fn scan_flags_a_planted_secret_and_passes_a_clean_repo() {
    let secret = format!("{}{}", "AKIA", "QYLPMN5HHHFPZAM2");
    let dirty = Fx::empty();
    let bare = bare_repo(
        dirty.dir.path(),
        "dirty",
        &[("settings.txt", &format!("aws_access_key_id = {secret}\n"))],
    );
    dirty.point_at(&bare);
    let out = dirty
        .cmd()
        .args(["scan", "--repo", "demo"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("AKIA****"))
        .stdout(predicate::str::contains("settings.txt:1"))
        .get_output()
        .stdout
        .clone();
    assert!(!String::from_utf8_lossy(&out).contains(&secret));

    let clean = Fx::empty();
    let bare = bare_repo(
        clean.dir.path(),
        "clean",
        &[("README.md", "nothing here\n")],
    );
    clean.point_at(&bare);
    clean
        .cmd()
        .args(["scan", "--repo", "demo"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no findings"));
    clean
        .cmd()
        .args(["scan", "--repo", "nope"])
        .assert()
        .code(2);
}

fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let status = raw.split_whitespace().nth(1)?.parse().ok()?;
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b.to_owned())?;
    Some((status, body))
}

fn wait_for(what: &str, limit: Duration, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < limit {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out after {limit:?} waiting for {what}");
}

/// Kills the server if a test fails before the clean shutdown.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn serve_runs_end_to_end_and_stops_on_sigterm() {
    let fx = Fx::empty();
    let bare = bare_repo(fx.dir.path(), "demo", &[("README.md", "hello world\n")]);
    fx.point_at(&bare);
    let key_out = fx
        .cmd()
        .args(["keygen", "--name", "e2e"])
        .output()
        .expect("keygen");
    let key = String::from_utf8_lossy(&key_out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("key: ").map(str::to_owned))
        .expect("key line");

    let log = fx.dir.path().join("serve.log");
    let child = Command::new(BIN)
        .arg("--config")
        .arg(&fx.config)
        .arg("serve")
        .env(ALLOW_LOCAL, "1")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).expect("log"))
        .spawn()
        .expect("spawn serve");
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("pid"));
    let mut server = Server(child);

    wait_for("/healthz", Duration::from_secs(30), || {
        http(fx.listen, "GET", "/healthz", &[], "").is_some_and(|(s, _)| s == 200)
    });
    wait_for("/readyz", Duration::from_secs(30), || {
        http(fx.admin, "GET", "/readyz", &[], "").is_some_and(|(s, _)| s == 200)
    });
    fx.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"ok\""));
    fx.cmd().arg("healthcheck").assert().success().stdout("");

    let (status, _) = http(
        fx.listen,
        "POST",
        "/mcp",
        &[("Content-Type", "application/json")],
        "{}",
    )
    .expect("mcp without key");
    assert_eq!(status, 401);
    let (status, body) = http(
        fx.listen,
        "POST",
        "/mcp",
        &[
            ("Authorization", &format!("Bearer {key}")),
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .expect("tools/list");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("list_repos"), "{body}");

    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("sigterm");
    let start = Instant::now();
    let exit = loop {
        if let Some(status) = server.0.try_wait().expect("wait") {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "server did not stop within 15s"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(exit.success(), "exit {exit:?}\n{logged}");
    assert!(logged.contains("\"event\":\"started\""), "{logged}");
}
