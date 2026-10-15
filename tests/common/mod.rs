//! Shared fixtures for the integration suites: local git hosts, config writer, server handle, MCP client.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::Value;

pub const BIN: &str = env!("CARGO_BIN_EXE_code-explorer");
pub const ALLOW_LOCAL: &str = "CODE_EXPLORER_ALLOW_LOCAL_REMOTES";
pub const BUTTON_MARKER: &str = "BUTTON_MARKER";
pub const OTHER_MARKER: &str = "OTHER_MARKER";
pub const ENV_SECRET: &str = "should-never-appear";
pub const SUBJECTS: [&str; 3] = [
    "Add README and Button component",
    "Add assets, config and bulk entries",
    "Relabel Button",
];

/// The fake AWS key is assembled at runtime so the source never holds it whole.
pub fn aws_secret() -> String {
    format!("{}{}", "AKIA", "QYLPMN5HHHFPZAM2")
}

pub fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

pub fn git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Creates a bare repo with one commit holding `files` and returns its path.
pub fn bare_repo(root: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
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

/// One raw HTTP/1.1 request over a plain socket; `None` while nothing listens.
pub fn http(
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

pub fn wait_for(what: &str, limit: Duration, mut ok: impl FnMut() -> bool) {
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
pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn long_comment_line() -> String {
    format!("// {}abcdefg", "abcdefghij".repeat(299))
}

/// A five line component; line 4 is 3000 characters long.
pub fn button_source(label: &str) -> String {
    format!(
        "import React from \"react\";\n// {BUTTON_MARKER}\nexport const Button = () => <button>{label}</button>;\n{}\nexport default Button;\n",
        long_comment_line()
    )
}

/// The two upstream repos and their bare clones, standing in for GitHub and Bitbucket.
pub struct Upstream {
    pub first_work: PathBuf,
    pub first_bare: PathBuf,
    pub other_bare: PathBuf,
    pub first_commits: Vec<String>,
}

impl Upstream {
    pub fn build(root: &Path) -> Upstream {
        let work = root.join("web-work");
        std::fs::create_dir_all(work.join("src/components")).expect("mkdir");
        git(&work, &["init", "-q", "-b", "main"]);
        let put = |rel: &str, content: &[u8]| {
            let path = work.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(path, content).expect("write");
        };
        let mut commits = Vec::new();

        put(
            "src/components/Button.tsx",
            button_source("OLD_LABEL").as_bytes(),
        );
        put(
            "src/components/index.ts",
            b"export { Button } from \"./Button\";\n",
        );
        put("README.md", b"# Web\n\nHello from the web repo.\n");
        put(".env.example", b"SECRET=changeme\n");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", SUBJECTS[0]]);
        commits.push(git(&work, &["rev-parse", "HEAD"]));

        put(
            "assets/logo.png",
            &[0x89, b'P', b'N', b'G', 0, 0, 0, 13, 0xff, 0],
        );
        put(
            "config/keys.txt",
            format!("aws_access_key_id = {}\n", aws_secret()).as_bytes(),
        );
        put(".env", format!("SECRET={ENV_SECRET}\n").as_bytes());
        for i in 0..80 {
            put(
                &format!("bulk/entry-{i:04}.dat"),
                format!("entry {i}\n").as_bytes(),
            );
        }
        std::os::unix::fs::symlink("README.md", work.join("link")).expect("symlink");
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", SUBJECTS[1]]);
        commits.push(git(&work, &["rev-parse", "HEAD"]));

        put(
            "src/components/Button.tsx",
            button_source("NEW_LABEL").as_bytes(),
        );
        git(&work, &["add", "."]);
        git(&work, &["commit", "-q", "-m", SUBJECTS[2]]);
        commits.push(git(&work, &["rev-parse", "HEAD"]));

        let bare = root.join("web.git");
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
        let other = bare_repo(
            root,
            "other",
            &[("notes.md", "# Notes\n\nOTHER_MARKER lives here.\n")],
        );
        Upstream {
            first_work: work,
            first_bare: bare,
            other_bare: other,
            first_commits: commits,
        }
    }

    /// Commits `content` as `rel` in the first repo and pushes it to its bare clone.
    pub fn push_first(&self, rel: &str, content: &str, subject: &str) -> String {
        let path = self.first_work.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, content).expect("write");
        git(&self.first_work, &["add", "."]);
        git(&self.first_work, &["commit", "-q", "-m", subject]);
        let bare = self.first_bare.to_str().expect("utf8").to_owned();
        git(&self.first_work, &["push", "-q", &bare, "main"]);
        git(&self.first_work, &["rev-parse", "HEAD"])
    }

    pub fn head(&self) -> String {
        git(&self.first_work, &["rev-parse", "HEAD"])
    }
}

/// Plaintext keys plus the `[[key]]` tables that go into keys.toml.
pub struct Keys {
    pub full: String,
    pub scoped: String,
    pub full_table: String,
    pub scoped_table: String,
}

impl Keys {
    /// Mints the two test keys once per process with `code-explorer keygen --print-only`.
    pub fn get() -> &'static Keys {
        static KEYS: OnceLock<Keys> = OnceLock::new();
        KEYS.get_or_init(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let keys_file = dir.path().join("keys.toml");
            std::fs::write(&keys_file, "").expect("keys");
            let config = dir.path().join("config.toml");
            let text = format!(
                "version = 1\n[server]\ndata_dir = {:?}\n[auth]\nkeys_file = {:?}\n[[repo]]\nid = \"web\"\nhost = \"github\"\npath = \"example-org/web\"\nbranch = \"main\"\n[[repo]]\nid = \"other\"\nhost = \"bitbucket\"\npath = \"example-workspace/other\"\nbranch = \"main\"\n",
                dir.path().join("data").display().to_string(),
                keys_file.display().to_string(),
            );
            std::fs::write(&config, text).expect("config");
            let mint = |name: &str, repos: Option<&str>| {
                let mut cmd = Command::new(BIN);
                cmd.arg("--config")
                    .arg(&config)
                    .env(ALLOW_LOCAL, "1")
                    .args(["keygen", "--name", name, "--print-only"]);
                if let Some(r) = repos {
                    cmd.args(["--repos", r]);
                }
                let out = cmd.output().expect("keygen");
                assert!(out.status.success(), "keygen {name} failed");
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                let key = stdout
                    .lines()
                    .find_map(|l| l.strip_prefix("key: ").map(str::to_owned))
                    .expect("key line");
                let table: String = stdout
                    .lines()
                    .filter(|l| !l.starts_with("key: "))
                    .collect::<Vec<_>>()
                    .join("\n");
                (key, table)
            };
            let (full, full_table) = mint("full", None);
            let (scoped, scoped_table) = mint("scoped", Some("other"));
            Keys {
                full,
                scoped,
                full_table,
                scoped_table,
            }
        })
    }

    pub fn keys_toml(&self) -> String {
        format!("{}\n\n{}\n", self.full_table, self.scoped_table)
    }
}

/// Optional TOML bodies for each section of the generated config.
#[derive(Default, Clone)]
pub struct Opts {
    pub limits: String,
    pub pull: String,
    pub scan: String,
    pub features: String,
    pub deny: String,
    pub failed_attempts: String,
    pub first_repo: String,
    pub other_repo: String,
    /// Extra `(id, repo lines)` entries that clone the first upstream repo.
    pub clones_of_first: Vec<(String, String)>,
}

fn section(name: &str, body: &str) -> String {
    if body.trim().is_empty() {
        String::new()
    } else {
        format!("[{name}]\n{body}\n")
    }
}

/// A temp dir holding the upstream repos, the config and the keys file of one server.
pub struct Env {
    pub up: Upstream,
    pub listen: u16,
    pub admin: u16,
    pub config: PathBuf,
    pub keys_file: PathBuf,
    pub dir: tempfile::TempDir,
}

impl Env {
    pub fn new(opts: &Opts) -> Env {
        let dir = tempfile::tempdir().expect("tempdir");
        let up = Upstream::build(dir.path());
        let keys_file = dir.path().join("keys.toml");
        std::fs::write(&keys_file, Keys::get().keys_toml()).expect("keys");
        let env = Env {
            up,
            listen: free_port(),
            admin: free_port(),
            config: dir.path().join("config.toml"),
            keys_file,
            dir,
        };
        env.write_config(opts);
        env
    }

    pub fn write_config(&self, o: &Opts) {
        let url = |p: &Path| format!("file://{}", p.display());
        let mut text = format!(
            "version = 1\n[server]\nlisten = \"127.0.0.1:{}\"\nadmin_listen = \"127.0.0.1:{}\"\ndata_dir = {:?}\n[auth]\nkeys_file = {:?}\n",
            self.listen,
            self.admin,
            self.dir.path().join("data").display().to_string(),
            self.keys_file.display().to_string(),
        );
        text.push_str(&section("auth.failed_attempts", &o.failed_attempts));
        text.push_str(&section("limits", &o.limits));
        text.push_str(&section("pull", &o.pull));
        text.push_str(&section("scan", &o.scan));
        text.push_str(&section("deny", &o.deny));
        text.push_str(&section("features", &o.features));
        text.push_str(&format!(
            "[[repo]]\nid = \"web\"\nhost = \"github\"\npath = \"example-org/web\"\nbranch = \"main\"\ndescription = \"Web UI components\"\nremote_url_override = {:?}\n{}\n",
            url(&self.up.first_bare),
            o.first_repo
        ));
        text.push_str(&format!(
            "[[repo]]\nid = \"other\"\nhost = \"bitbucket\"\npath = \"example-workspace/other\"\nbranch = \"main\"\ndescription = \"Other notes\"\nremote_url_override = {:?}\n{}\n",
            url(&self.up.other_bare),
            o.other_repo
        ));
        for (id, extra) in &o.clones_of_first {
            text.push_str(&format!(
                "[[repo]]\nid = {id:?}\nhost = \"github\"\npath = \"example-org/web\"\nbranch = \"main\"\ndescription = \"Clone of web\"\nremote_url_override = {:?}\n{extra}\n",
                url(&self.up.first_bare),
            ));
        }
        std::fs::write(&self.config, text).expect("config");
    }
}

/// A running `code-explorer serve` process with its environment.
pub struct Server {
    child: ChildGuard,
    pub env: Env,
    pub log: PathBuf,
}

/// Kills the server and removes `dir` once the test process is gone, for servers that live in statics.
fn spawn_watchdog(child: u32, dir: &Path) {
    let script = format!(
        "parent={}; while kill -0 $parent 2>/dev/null && kill -0 {child} 2>/dev/null; do sleep 1; done; if ! kill -0 $parent 2>/dev/null; then kill {child} 2>/dev/null; sleep 2; rm -rf '{}'; fi",
        std::process::id(),
        dir.display()
    );
    let _ = Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

impl Server {
    /// Starts the server and waits up to 30s for `/readyz` to answer 200.
    pub fn start(opts: &Opts) -> Server {
        let env = Env::new(opts);
        let log = env.dir.path().join("serve.log");
        let child = Command::new(BIN)
            .arg("--config")
            .arg(&env.config)
            .arg("serve")
            .env(ALLOW_LOCAL, "1")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).expect("log"))
            .spawn()
            .expect("spawn serve");
        spawn_watchdog(child.id(), env.dir.path());
        let server = Server {
            child: ChildGuard(child),
            env,
            log,
        };
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            if http(server.env.admin, "GET", "/readyz", &[], "").is_some_and(|(s, _)| s == 200) {
                return server;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "server not ready after 30s:\n{}",
            std::fs::read_to_string(&server.log).unwrap_or_default()
        );
    }

    pub fn port(&self) -> u16 {
        self.env.listen
    }

    pub fn admin_port(&self) -> u16 {
        self.env.admin
    }

    pub fn mcp_url(&self) -> String {
        format!("http://127.0.0.1:{}/mcp", self.env.listen)
    }

    pub fn full_key(&self) -> &'static str {
        &Keys::get().full
    }

    pub fn scoped_key(&self) -> &'static str {
        &Keys::get().scoped
    }

    pub fn readyz(&self) -> Value {
        let (status, body) =
            http(self.env.admin, "GET", "/readyz", &[], "").expect("readyz reachable");
        assert!(status == 200 || status == 503, "readyz status {status}");
        serde_json::from_str(&body).expect("readyz json")
    }

    /// The `/readyz` entry of one repo.
    pub fn repo_health(&self, id: &str) -> Value {
        self.readyz()["repos"]
            .as_array()
            .and_then(|r| r.iter().find(|x| x["id"] == id))
            .cloned()
            .unwrap_or(Value::Null)
    }

    pub async fn client(&self, key: &str) -> Mcp {
        Mcp::connect(self.env.listen, key).await
    }

    pub async fn full(&self) -> Mcp {
        self.client(self.full_key()).await
    }

    pub async fn scoped(&self) -> Mcp {
        self.client(self.scoped_key()).await
    }

    pub fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// A connected rmcp client for one key.
pub struct Mcp {
    pub svc: RunningService<RoleClient, ClientConfig>,
}

impl Mcp {
    pub async fn connect(port: u16, key: &str) -> Mcp {
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(format!("http://127.0.0.1:{port}/mcp"))
                .auth_header(key),
        );
        let svc = ClientConfig::default()
            .serve(transport)
            .await
            .expect("mcp initialize");
        Mcp { svc }
    }

    pub async fn tools(&self) -> Vec<Value> {
        let tools = self.svc.list_all_tools().await.expect("tools/list");
        tools
            .iter()
            .map(|t| serde_json::to_value(t).expect("tool json"))
            .collect()
    }

    pub async fn call(&self, name: &str, args: Value) -> Reply {
        let Value::Object(map) = args else {
            panic!("arguments must be a JSON object");
        };
        let params = CallToolRequestParams::new(name.to_owned()).with_arguments(map);
        let result = self
            .svc
            .call_tool(params)
            .await
            .unwrap_or_else(|e| panic!("protocol error calling {name}: {e}"));
        Reply {
            raw: serde_json::to_value(&result).expect("result json"),
        }
    }
}

/// A tool result in JSON form with accessors for the envelope.
pub struct Reply {
    pub raw: Value,
}

impl Reply {
    pub fn is_error(&self) -> bool {
        self.raw["isError"].as_bool().unwrap_or(false)
    }

    pub fn data(&self) -> &Value {
        &self.raw["structuredContent"]
    }

    pub fn text(&self) -> String {
        self.raw["content"]
            .as_array()
            .map(|c| {
                c.iter()
                    .filter_map(|b| b["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }

    pub fn error_code(&self) -> Option<&str> {
        self.data()["error"]["code"].as_str()
    }

    pub fn error_message(&self) -> String {
        self.data()["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    pub fn notice_codes(&self) -> Vec<String> {
        self.data()["notices"]
            .as_array()
            .map(|n| {
                n.iter()
                    .filter_map(|x| x["code"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_notice(&self, code: &str) -> bool {
        self.notice_codes().iter().any(|c| c == code)
    }

    /// Panics with the full result unless the call succeeded.
    pub fn ok(&self) -> &Value {
        assert!(!self.is_error(), "expected success, got {}", self.raw);
        self.data()
    }

    /// Panics unless the call failed with `code`.
    pub fn expect_error(&self, code: &str) -> &Self {
        assert!(self.is_error(), "expected error {code}, got {}", self.raw);
        assert_eq!(self.error_code(), Some(code), "{}", self.raw);
        self
    }
}
