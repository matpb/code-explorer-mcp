//! End-to-end tests of the MCP tools over the real streamable HTTP transport against local git hosts.

mod common;

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

const ACCEPT: &str = "application/json, text/event-stream";

fn opts(f: impl FnOnce(&mut Opts)) -> Opts {
    let mut o = Opts::default();
    f(&mut o);
    o
}

fn default_server() -> &'static Server {
    static S: OnceLock<Server> = OnceLock::new();
    S.get_or_init(|| Server::start(&Opts::default()))
}

fn feature_server() -> &'static Server {
    static S: OnceLock<Server> = OnceLock::new();
    S.get_or_init(|| {
        Server::start(&opts(|o| {
            o.features = "blame = true\nfile_at_commit = true".into();
            o.deny = "allow = [\"**/.env.example\"]".into();
        }))
    })
}

fn tight_server() -> &'static Server {
    static S: OnceLock<Server> = OnceLock::new();
    S.get_or_init(|| {
        Server::start(&opts(|o| {
            o.limits = "max_file_bytes = 2000\nmax_response_bytes = 4096\nmax_concurrent_workers = 2\nqueue_timeout = \"20ms\"".into();
            o.pull = "depth = 1".into();
        }))
    })
}

fn scan_server() -> &'static Server {
    static S: OnceLock<Server> = OnceLock::new();
    S.get_or_init(|| {
        Server::start(&opts(|o| {
            o.clones_of_first = vec![
                ("web-warn".into(), "scan_policy = \"warn\"".into()),
                ("web-block".into(), "scan_policy = \"block\"".into()),
            ];
        }))
    })
}

fn strs(v: &Value, field: &str, key: &str) -> Vec<String> {
    v[field]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e[key].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn rpc(id: u32, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// The JSON-RPC message of a response body, plain JSON or one SSE `data:` event.
fn rpc_json(body: &str) -> Value {
    let payload = body
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .unwrap_or(body);
    serde_json::from_str(payload.trim())
        .unwrap_or_else(|e| panic!("bad JSON-RPC body {body:?}: {e}"))
}

async fn post(
    http: &reqwest::Client,
    url: &str,
    key: Option<&str>,
    extra: &[(&str, &str)],
    body: String,
) -> reqwest::Response {
    let mut req = http
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", ACCEPT)
        .body(body);
    if let Some(k) = key {
        req = req.header("Authorization", format!("Bearer {k}"));
    }
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    req.send().await.expect("request sent")
}

fn list_repos_call() -> String {
    rpc(
        2,
        "tools/call",
        json!({"name": "list_repos", "arguments": {}}),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn initialize_and_tools_list() {
    let s = default_server();
    let full = s.full().await;
    let info = full.svc.peer_info().expect("peer info");
    let name = info.server_info.as_ref().map(|i| i.name.clone());
    assert_eq!(name.as_deref(), Some("code-explorer"));

    let tools = full.tools().await;
    let mut names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "glob",
            "grep",
            "list_repos",
            "list_tree",
            "log",
            "read_file"
        ]
    );
    for t in &tools {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{}", t["name"]);
        let desc = t["description"].as_str().unwrap_or_default().to_lowercase();
        assert!(desc.contains("untrusted"), "{}: {desc}", t["name"]);
    }
    let tree = tools
        .iter()
        .find(|t| t["name"] == "list_tree")
        .expect("list_tree");
    assert_eq!(
        tree["inputSchema"]["properties"]["repo"]["enum"],
        json!(["web", "other"])
    );
    let read = tools
        .iter()
        .find(|t| t["name"] == "read_file")
        .expect("read_file");
    assert!(read["inputSchema"]["properties"].get("commit").is_none());

    let scoped = s.scoped().await.tools().await;
    for name in ["list_tree", "glob", "read_file", "log"] {
        let t = scoped.iter().find(|t| t["name"] == name).expect("tool");
        assert_eq!(
            t["inputSchema"]["properties"]["repo"]["enum"],
            json!(["other"]),
            "{name}"
        );
    }
    let grep = scoped.iter().find(|t| t["name"] == "grep").expect("grep");
    assert_eq!(
        grep["inputSchema"]["properties"]["repos"]["items"]["enum"],
        json!(["other"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn feature_flags_add_blame_and_commit_param() {
    let tools = feature_server().full().await.tools().await;
    assert_eq!(tools.len(), 7);
    assert!(tools.iter().any(|t| t["name"] == "blame"));
    let read = tools
        .iter()
        .find(|t| t["name"] == "read_file")
        .expect("read_file");
    assert!(read["inputSchema"]["properties"].get("commit").is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_client_works_without_session_header() {
    let s = default_server();
    let http = reqwest::Client::new();
    let init = rpc(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "legacy", "version": "1"}}),
    );
    let resp = post(&http, &s.mcp_url(), Some(s.full_key()), &[], init).await;
    assert_eq!(resp.status(), 200);
    let body = rpc_json(&resp.text().await.expect("body"));
    assert_eq!(body["result"]["serverInfo"]["name"], "code-explorer");

    let resp = post(
        &http,
        &s.mcp_url(),
        Some(s.full_key()),
        &[],
        rpc(2, "tools/list", json!({})),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = rpc_json(&resp.text().await.expect("body"));
    assert_eq!(body["result"]["tools"].as_array().map(Vec::len), Some(6));

    let resp = post(
        &http,
        &s.mcp_url(),
        Some(s.full_key()),
        &[],
        list_repos_call(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = rpc_json(&resp.text().await.expect("body"));
    assert_eq!(body["result"]["structuredContent"]["repos"][0]["id"], "web");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_repos_reports_both_repos_ready() {
    let s = default_server();
    let c = s.full().await;
    let r = c.call("list_repos", json!({})).await;
    let data = r.ok();
    let repos = data["repos"].as_array().expect("repos");
    assert_eq!(repos.len(), 2);

    let web = &repos[0];
    assert_eq!(web["id"], "web");
    assert_eq!(web["host"], "github");
    assert_eq!(web["branch"], "main");
    assert_eq!(web["status"], "ready");
    assert_eq!(web["commit"], s.env.up.head());
    assert_eq!(web["commit_subject"], SUBJECTS[2]);
    assert_eq!(web["secrets_redacted"], 1);
    assert_eq!(web["stale_seconds"], 0);
    assert_eq!(web["history_depth"], 200);

    let other_head = git(&s.env.up.other_bare, &["rev-parse", "main"]);
    let other = &repos[1];
    assert_eq!(other["id"], "other");
    assert_eq!(other["host"], "bitbucket");
    assert_eq!(other["status"], "ready");
    assert_eq!(other["commit"], other_head);
    assert_eq!(other["secrets_redacted"], 0);

    let scoped = s.scoped().await.call("list_repos", json!({})).await;
    assert_eq!(strs(scoped.ok(), "repos", "id"), ["other"]);
    assert!(!scoped.raw.to_string().contains("\"web\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tree_root_listing_hides_denied_files() {
    let c = default_server().full().await;
    let r = c.call("list_tree", json!({"repo": "web"})).await;
    let data = r.ok();
    let entries = data["entries"].as_array().expect("entries");
    let find = |p: &str| entries.iter().find(|e| e["path"] == p);
    assert_eq!(find("src").expect("src")["type"], "dir");
    assert_eq!(find("README.md").expect("README")["type"], "file");
    let link = find("link").expect("link");
    assert_eq!(link["type"], "symlink");
    assert_eq!(link["target"], "README.md");
    assert!(find(".env").is_none());
    assert!(find(".env.example").is_none());
    assert_eq!(data["source"]["repo"], "web");
    assert_eq!(data["source"]["commit"], default_server().env.up.head());
    assert!(r.text().contains("symlink  link -> README.md"));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tree_depth_and_max_entries() {
    let c = default_server().full().await;
    let shallow = c
        .call("list_tree", json!({"repo": "web", "depth": 1}))
        .await;
    let paths = strs(shallow.ok(), "entries", "path");
    assert!(paths.iter().all(|p| !p.contains('/')), "{paths:?}");
    let src = shallow.data()["entries"]
        .as_array()
        .and_then(|e| e.iter().find(|x| x["path"] == "src"))
        .expect("src");
    assert_eq!(src["children_truncated"], true);

    let deep = c
        .call(
            "list_tree",
            json!({"repo": "web", "path": "src", "depth": 3}),
        )
        .await;
    assert!(strs(deep.ok(), "entries", "path").contains(&"src/components/Button.tsx".to_owned()));
    assert!(deep.notice_codes().is_empty());

    let capped = c
        .call("list_tree", json!({"repo": "web", "max_entries": 3}))
        .await;
    assert_eq!(capped.ok()["entries"].as_array().map(Vec::len), Some(3));
    assert!(capped.has_notice("output_truncated"));
    assert!(capped.raw.to_string().contains("max_entries"));

    c.call("list_tree", json!({"repo": "web", "depth": 0}))
        .await
        .expect_error("invalid_argument");
    c.call("list_tree", json!({"repo": "web", "depth": 7}))
        .await
        .expect_error("invalid_argument");
    c.call("list_tree", json!({"repo": "web", "max_entries": 5000}))
        .await
        .expect_error("invalid_argument");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tree_errors() {
    let s = default_server();
    let c = s.full().await;
    c.call("list_tree", json!({"repo": "web", "path": "nope"}))
        .await
        .expect_error("path_not_found");
    c.call("list_tree", json!({"repo": "web", "path": "README.md"}))
        .await
        .expect_error("not_a_directory");
    c.call("list_tree", json!({"repo": "web", "path": ".env"}))
        .await
        .expect_error("path_denied");
    c.call("list_tree", json!({"repo": "web", "path": "../etc"}))
        .await
        .expect_error("invalid_argument");
    c.call("list_tree", json!({"repo": "nosuch"}))
        .await
        .expect_error("unknown_repo");
    c.call("list_tree", json!({"repo": "web", "bogus": true}))
        .await
        .expect_error("invalid_argument");

    let scoped = s.scoped().await;
    let r = scoped.call("list_tree", json!({"repo": "web"})).await;
    r.expect_error("unknown_repo");
    assert!(
        r.error_message().contains("Your repos: other."),
        "{}",
        r.error_message()
    );
    let ok = scoped.call("list_tree", json!({"repo": "other"})).await;
    assert_eq!(strs(ok.ok(), "entries", "path"), ["notes.md"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn glob_matches_patterns() {
    let c = default_server().full().await;
    let tsx = c
        .call("glob", json!({"repo": "web", "pattern": "**/*.tsx"}))
        .await;
    assert_eq!(
        strs(tsx.ok(), "files", "path"),
        ["src/components/Button.tsx"]
    );
    assert_eq!(tsx.data()["total_matched"], 1);

    let ts = c
        .call("glob", json!({"repo": "web", "pattern": "*.ts"}))
        .await;
    assert_eq!(strs(ts.ok(), "files", "path"), ["src/components/index.ts"]);

    let scoped_path = c
        .call(
            "glob",
            json!({"repo": "web", "pattern": "*.tsx", "path": "src"}),
        )
        .await;
    assert_eq!(
        strs(scoped_path.ok(), "files", "path"),
        ["src/components/Button.tsx"]
    );

    let ci = c
        .call(
            "glob",
            json!({"repo": "web", "pattern": "readme.MD", "case_insensitive": true}),
        )
        .await;
    assert_eq!(strs(ci.ok(), "files", "path"), ["README.md"]);
    let cs = c
        .call("glob", json!({"repo": "web", "pattern": "readme.MD"}))
        .await;
    assert!(strs(cs.ok(), "files", "path").is_empty());

    let capped = c
        .call(
            "glob",
            json!({"repo": "web", "pattern": "bulk/*.dat", "max_results": 5}),
        )
        .await;
    assert_eq!(capped.ok()["files"].as_array().map(Vec::len), Some(5));
    assert_eq!(capped.data()["total_matched"], 80);

    let env = c
        .call("glob", json!({"repo": "web", "pattern": ".env*"}))
        .await;
    assert!(strs(env.ok(), "files", "path").is_empty(), "{}", env.raw);

    c.call("glob", json!({"repo": "web", "pattern": "["}))
        .await
        .expect_error("invalid_pattern");
    c.call("glob", json!({"repo": "web", "pattern": ""}))
        .await
        .expect_error("invalid_argument");
    c.call(
        "glob",
        json!({"repo": "web", "pattern": "*", "path": "README.md"}),
    )
    .await
    .expect_error("not_a_directory");
    c.call(
        "glob",
        json!({"repo": "web", "pattern": "*", "path": "nope"}),
    )
    .await
    .expect_error("path_not_found");
    c.call(
        "glob",
        json!({"repo": "web", "pattern": "*", "path": ".env"}),
    )
    .await
    .expect_error("path_denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn glob_allow_list_exposes_env_example() {
    let c = feature_server().full().await;
    let env = c
        .call("glob", json!({"repo": "web", "pattern": ".env*"}))
        .await;
    assert_eq!(strs(env.ok(), "files", "path"), [".env.example"]);
    let read = c
        .call("read_file", json!({"repo": "web", "path": ".env.example"}))
        .await;
    assert_eq!(read.ok()["content"], "SECRET=changeme");
    c.call("read_file", json!({"repo": "web", "path": ".env"}))
        .await
        .expect_error("path_denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn read_file_content_lines_and_permalinks() {
    let s = default_server();
    let c = s.full().await;
    let head = s.env.up.head();

    let readme = c
        .call("read_file", json!({"repo": "web", "path": "README.md"}))
        .await;
    let data = readme.ok();
    assert_eq!(data["content"], "# Web\n\nHello from the web repo.");
    assert_eq!(data["start_line"], 1);
    assert_eq!(data["end_line"], 3);
    assert_eq!(data["total_lines"], 3);
    assert!(
        readme
            .text()
            .contains("1\t# Web\n2\t\n3\tHello from the web repo.")
    );

    let part = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "README.md", "offset": 3, "limit": 1}),
        )
        .await;
    assert_eq!(part.ok()["content"], "Hello from the web repo.");
    assert_eq!(
        part.data()["permalink"],
        format!("https://github.com/example-org/web/blob/{head}/README.md#L3")
    );

    let button = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "src/components/Button.tsx"}),
        )
        .await;
    let data = button.ok();
    assert_eq!(
        data["permalink"],
        format!("https://github.com/example-org/web/blob/{head}/src/components/Button.tsx#L1-L5")
    );
    let content = data["content"].as_str().expect("content");
    assert!(content.contains(BUTTON_MARKER) && content.contains("NEW_LABEL"));
    assert!(content.contains("[cut at 2000 chars]"));
    assert!(button.has_notice("output_truncated"));
    assert_eq!(data["total_lines"], 5);
    assert_eq!(data["source"]["commit"], head);

    let notes = s.full().await;
    let other_head = git(&s.env.up.other_bare, &["rev-parse", "main"]);
    let r = notes
        .call("read_file", json!({"repo": "other", "path": "notes.md"}))
        .await;
    assert_eq!(
        r.ok()["permalink"],
        format!(
            "https://bitbucket.org/example-workspace/other/src/{other_head}/notes.md#lines-1:3"
        )
    );

    let link = c
        .call("read_file", json!({"repo": "web", "path": "link"}))
        .await;
    assert_eq!(link.ok()["content"], "README.md");
}

#[tokio::test(flavor = "multi_thread")]
async fn read_file_errors() {
    let c = default_server().full().await;
    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "offset": 99}),
    )
    .await
    .expect_error("offset_out_of_range");
    c.call(
        "read_file",
        json!({"repo": "web", "path": "assets/logo.png"}),
    )
    .await
    .expect_error("binary_file");
    c.call("read_file", json!({"repo": "web", "path": "src"}))
        .await
        .expect_error("not_a_file");
    c.call("read_file", json!({"repo": "web", "path": ""}))
        .await
        .expect_error("not_a_file");
    c.call("read_file", json!({"repo": "web", "path": ".env"}))
        .await
        .expect_error("path_denied");
    c.call("read_file", json!({"repo": "web", "path": ".env.example"}))
        .await
        .expect_error("path_denied");
    c.call("read_file", json!({"repo": "web", "path": "/etc/passwd"}))
        .await
        .expect_error("invalid_argument");
    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "limit": 0}),
    )
    .await
    .expect_error("invalid_argument");
    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "limit": 5000}),
    )
    .await
    .expect_error("invalid_argument");
    c.call("read_file", json!({"repo": "nosuch", "path": "README.md"}))
        .await
        .expect_error("unknown_repo");

    let missing = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "components/Button.tsx"}),
        )
        .await;
    missing.expect_error("path_not_found");
    assert!(
        missing
            .error_message()
            .contains("Did you mean src/components/Button.tsx"),
        "{}",
        missing.error_message()
    );
    let no_hint = c
        .call("read_file", json!({"repo": "web", "path": "zzzzzzzz.qq"}))
        .await;
    no_hint.expect_error("path_not_found");

    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "commit": "abcd1234"}),
    )
    .await
    .expect_error("invalid_argument");
}

#[tokio::test(flavor = "multi_thread")]
async fn read_file_redacts_secrets_everywhere() {
    let c = default_server().full().await;
    let secret = aws_secret();

    let r = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "config/keys.txt"}),
        )
        .await;
    let data = r.ok();
    assert_eq!(
        data["content"],
        "aws_access_key_id = [REDACTED:aws-access-token]"
    );
    assert!(r.has_notice("secrets_redacted"));
    assert!(!r.raw.to_string().contains(&secret));
    assert!(!r.raw.to_string().contains("QYLPMN5HHHFPZAM2"));

    let g = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "aws_access_key_id"}),
        )
        .await;
    let hit = &g.ok()["matches"][0];
    assert_eq!(hit["path"], "config/keys.txt");
    assert_eq!(
        hit["text"],
        "aws_access_key_id = [REDACTED:aws-access-token]"
    );
    assert!(g.has_notice("secrets_redacted"));
    assert!(!g.raw.to_string().contains("QYLPMN5HHHFPZAM2"));

    let by_secret = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "AKIA", "fixed_strings": true}),
        )
        .await;
    assert!(!by_secret.raw.to_string().contains("QYLPMN5HHHFPZAM2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn read_file_commit_param_selects_older_content() {
    let s = feature_server();
    let c = s.full().await;
    let commits = &s.env.up.first_commits;
    let old = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "src/components/Button.tsx", "commit": &commits[0]}),
        )
        .await;
    let data = old.ok();
    let content = data["content"].as_str().expect("content");
    assert!(content.contains("OLD_LABEL") && !content.contains("NEW_LABEL"));
    assert_eq!(data["source"]["commit"], commits[0]);
    assert_eq!(
        data["permalink"],
        format!(
            "https://github.com/example-org/web/blob/{}/src/components/Button.tsx#L1-L5",
            commits[0]
        )
    );

    let short = &commits[0][..10];
    let by_prefix = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "README.md", "commit": short}),
        )
        .await;
    assert_eq!(by_prefix.ok()["source"]["commit"], commits[0]);

    let current = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "src/components/Button.tsx"}),
        )
        .await;
    assert!(
        current.ok()["content"]
            .as_str()
            .unwrap_or_default()
            .contains("NEW_LABEL")
    );

    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "commit": "deadbeef"}),
    )
    .await
    .expect_error("history_unavailable");
    c.call(
        "read_file",
        json!({"repo": "web", "path": "README.md", "commit": "not-a-commit"}),
    )
    .await
    .expect_error("invalid_argument");
    c.call(
        "read_file",
        json!({"repo": "web", "path": "assets/logo.png", "commit": &commits[0]}),
    )
    .await
    .expect_error("path_not_found");
}

#[tokio::test(flavor = "multi_thread")]
async fn tight_limits_refuse_large_files_and_cap_responses() {
    let c = tight_server().full().await;
    c.call(
        "read_file",
        json!({"repo": "web", "path": "src/components/Button.tsx"}),
    )
    .await
    .expect_error("file_too_large");
    let small = c
        .call("read_file", json!({"repo": "web", "path": "README.md"}))
        .await;
    assert_eq!(small.ok()["total_lines"], 3);

    let listing = c
        .call("list_tree", json!({"repo": "web", "path": "bulk"}))
        .await;
    let kept = listing.ok()["entries"].as_array().map_or(0, Vec::len);
    assert!(kept > 0 && kept < 80, "kept {kept}");
    assert!(listing.has_notice("output_truncated"));
    assert!(listing.raw.to_string().contains("max_response_bytes"));
    assert!(serde_json::to_vec(listing.data()).expect("json").len() <= 4096);

    let files = c
        .call("glob", json!({"repo": "web", "pattern": "bulk/*.dat"}))
        .await;
    assert!(files.has_notice("output_truncated"));
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_finds_marker_with_permalink() {
    let s = default_server();
    let c = s.full().await;
    let r = c
        .call("grep", json!({"repos": ["web"], "pattern": BUTTON_MARKER}))
        .await;
    let data = r.ok();
    let matches = data["matches"].as_array().expect("matches");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["repo"], "web");
    assert_eq!(matches[0]["path"], "src/components/Button.tsx");
    assert_eq!(matches[0]["line"], 2);
    assert_eq!(matches[0]["text"], "// BUTTON_MARKER");
    assert_eq!(
        matches[0]["permalink"],
        format!(
            "https://github.com/example-org/web/blob/{}/src/components/Button.tsx#L2",
            s.env.up.head()
        )
    );
    assert_eq!(data["sources"].as_array().map(Vec::len), Some(1));
    assert_eq!(data["total_matches_seen"], 1);
    assert!(
        r.text()
            .contains("web:src/components/Button.tsx:2: // BUTTON_MARKER")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_defaults_to_every_repo_of_the_key() {
    let s = default_server();
    let r = s
        .full()
        .await
        .call("grep", json!({"pattern": OTHER_MARKER}))
        .await;
    let data = r.ok();
    assert_eq!(data["sources"].as_array().map(Vec::len), Some(2));
    assert_eq!(strs(data, "matches", "repo"), ["other"]);
    assert_eq!(strs(data, "matches", "path"), ["notes.md"]);

    let both = s
        .full()
        .await
        .call("grep", json!({"pattern": "_MARKER", "case": "sensitive"}))
        .await;
    let mut repos = strs(both.ok(), "matches", "repo");
    repos.sort();
    assert_eq!(repos, ["other", "web"]);

    let scoped = s
        .scoped()
        .await
        .call("grep", json!({"pattern": "_MARKER"}))
        .await;
    assert_eq!(strs(scoped.ok(), "matches", "repo"), ["other"]);
    assert_eq!(scoped.data()["sources"].as_array().map(Vec::len), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_fixed_strings_case_and_word() {
    let c = default_server().full().await;
    let literal = "Button = () =>";
    let fixed = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": literal, "fixed_strings": true}),
        )
        .await;
    assert_eq!(fixed.ok()["matches"].as_array().map(Vec::len), Some(1));
    let regex = c
        .call("grep", json!({"repos": ["web"], "pattern": literal}))
        .await;
    assert!(regex.ok()["matches"].as_array().is_some_and(Vec::is_empty));

    let smart = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "button_marker"}),
        )
        .await;
    assert_eq!(smart.ok()["matches"].as_array().map(Vec::len), Some(1));
    let sensitive = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "button_marker", "case": "sensitive"}),
        )
        .await;
    assert!(
        sensitive.ok()["matches"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let insensitive = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "BUTTON_marker", "case": "insensitive"}),
        )
        .await;
    assert_eq!(
        insensitive.ok()["matches"].as_array().map(Vec::len),
        Some(1)
    );

    let partial = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Butto", "word": true}),
        )
        .await;
    assert!(
        partial.ok()["matches"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    let whole = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "word": true}),
        )
        .await;
    assert!(
        !whole.ok()["matches"]
            .as_array()
            .expect("matches")
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_context_lines() {
    let c = default_server().full().await;
    let r = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": BUTTON_MARKER, "context_before": 1, "context_after": 1}),
        )
        .await;
    let hit = &r.ok()["matches"][0];
    assert_eq!(hit["before"], json!(["import React from \"react\";"]));
    let after = hit["after"][0].as_str().expect("after line");
    assert!(after.contains("NEW_LABEL"), "{after}");
    assert!(
        r.text()
            .contains("web:src/components/Button.tsx-1- import React")
    );
    c.call(
        "grep",
        json!({"repos": ["web"], "pattern": "x", "context_before": 11}),
    )
    .await
    .expect_error("invalid_argument");
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_output_modes_and_filters() {
    let c = default_server().full().await;
    let files = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "output": "files"}),
        )
        .await;
    assert_eq!(
        strs(files.ok(), "files", "path"),
        ["src/components/Button.tsx", "src/components/index.ts"]
    );
    assert!(files.data().get("matches").is_none());

    let counts = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "output": "count"}),
        )
        .await;
    let data = counts.ok();
    assert_eq!(data["files"][0]["count"], 2);
    assert_eq!(data["files"][1]["count"], 1);
    assert_eq!(data["total_matches_seen"], 3);

    let only_ts = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "output": "files", "glob": ["*.ts"]}),
        )
        .await;
    assert_eq!(
        strs(only_ts.ok(), "files", "path"),
        ["src/components/index.ts"]
    );
    let not_ts = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "output": "files", "glob": ["!*.ts"]}),
        )
        .await;
    assert_eq!(
        strs(not_ts.ok(), "files", "path"),
        ["src/components/Button.tsx"]
    );

    let typed = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "output": "files", "type": ["ts"]}),
        )
        .await;
    assert_eq!(
        strs(typed.ok(), "files", "path"),
        ["src/components/Button.tsx", "src/components/index.ts"]
    );
    let md = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Hello", "output": "files", "type": ["md"]}),
        )
        .await;
    assert_eq!(strs(md.ok(), "files", "path"), ["README.md"]);

    let in_path = c
        .call("grep", json!({"repos": ["web"], "pattern": "entry", "path": "bulk", "output": "count", "max_results": 3}))
        .await;
    assert_eq!(in_path.ok()["files"].as_array().map(Vec::len), Some(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_errors() {
    let s = default_server();
    let c = s.full().await;
    c.call(
        "grep",
        json!({"pattern": "x", "repos": ["web", "other"], "path": "src"}),
    )
    .await
    .expect_error("invalid_argument");
    c.call("grep", json!({"pattern": "("}))
        .await
        .expect_error("invalid_pattern");
    c.call("grep", json!({"pattern": "\\w{1000}"}))
        .await
        .expect_error("pattern_too_complex");
    c.call("grep", json!({"pattern": ""}))
        .await
        .expect_error("invalid_argument");
    c.call("grep", json!({"pattern": "x", "type": ["nosuchtype"]}))
        .await
        .expect_error("invalid_argument");
    c.call("grep", json!({"pattern": "x", "repos": ["nosuch"]}))
        .await
        .expect_error("unknown_repo");
    c.call(
        "grep",
        json!({"pattern": "x", "repos": ["web"], "path": "nope"}),
    )
    .await
    .expect_error("path_not_found");
    c.call(
        "grep",
        json!({"pattern": "x", "repos": ["web"], "path": ".env"}),
    )
    .await
    .expect_error("path_denied");
    c.call("grep", json!({"pattern": "x", "max_results": 0}))
        .await
        .expect_error("invalid_argument");

    let scoped = s.scoped().await;
    let r = scoped
        .call("grep", json!({"pattern": BUTTON_MARKER, "repos": ["web"]}))
        .await;
    r.expect_error("unknown_repo");
    assert!(r.error_message().contains("Your repos: other."));
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_result_caps_add_notices() {
    let c = default_server().full().await;
    let capped = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "entry", "glob": ["bulk/**"], "max_results": 1}),
        )
        .await;
    assert_eq!(capped.ok()["matches"].as_array().map(Vec::len), Some(1));
    assert_eq!(capped.data()["total_matches_seen"], 80);
    assert!(capped.has_notice("output_truncated"));
    assert!(capped.raw.to_string().contains("max_results"));

    let per_file = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "Button", "max_per_file": 1}),
        )
        .await;
    assert!(per_file.has_notice("output_truncated"));
    assert!(per_file.raw.to_string().contains("max_per_file"));

    let long = c
        .call("grep", json!({"repos": ["web"], "pattern": "abcdefghij"}))
        .await;
    assert!(long.has_notice("output_truncated"));
    assert!(
        long.ok()["matches"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("[cut at 2000 chars]")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grep_never_returns_denied_paths() {
    let c = default_server().full().await;
    for pattern in [ENV_SECRET, "SECRET", "changeme"] {
        let r = c.call("grep", json!({"pattern": pattern})).await;
        let data = r.ok();
        assert!(
            data["matches"].as_array().is_some_and(|m| m
                .iter()
                .all(|x| !x["path"].as_str().unwrap_or_default().starts_with(".env"))),
            "{pattern}: {}",
            r.raw
        );
        assert!(!r.raw.to_string().contains(ENV_SECRET));
    }
    let direct = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": ENV_SECRET, "fixed_strings": true}),
        )
        .await;
    assert_eq!(direct.ok()["total_matches_seen"], 0);
    assert!(direct.text().starts_with("No matches."));
}

#[tokio::test(flavor = "multi_thread")]
async fn log_lists_commits_newest_first() {
    let s = default_server();
    let c = s.full().await;
    let commits = &s.env.up.first_commits;
    let r = c.call("log", json!({"repo": "web"})).await;
    let data = r.ok();
    assert_eq!(
        strs(data, "commits", "subject"),
        [SUBJECTS[2], SUBJECTS[1], SUBJECTS[0]]
    );
    assert_eq!(
        strs(data, "commits", "commit"),
        [
            commits[2].as_str(),
            commits[1].as_str(),
            commits[0].as_str()
        ]
    );
    assert_eq!(data["commits"][0]["parents"], json!([commits[1]]));
    assert_eq!(data["commits"][0]["author_name"], "Test");
    assert!(data["commits"][0].get("author_email").is_none());
    assert_eq!(data["history_truncated"], false);
    assert!(!r.has_notice("history_truncated"));

    let two = c.call("log", json!({"repo": "web", "max_count": 2})).await;
    assert_eq!(
        strs(two.ok(), "commits", "subject"),
        [SUBJECTS[2], SUBJECTS[1]]
    );

    let by_path = c
        .call(
            "log",
            json!({"repo": "web", "path": "src/components/Button.tsx"}),
        )
        .await;
    assert_eq!(
        strs(by_path.ok(), "commits", "subject"),
        [SUBJECTS[2], SUBJECTS[0]]
    );
    let by_dir = c
        .call("log", json!({"repo": "web", "path": "assets"}))
        .await;
    assert_eq!(strs(by_dir.ok(), "commits", "subject"), [SUBJECTS[1]]);

    let with_files = c
        .call("log", json!({"repo": "web", "include_files": true}))
        .await;
    let first = &with_files.ok()["commits"][0]["files"];
    assert_eq!(
        first,
        &json!([{"status": "M", "path": "src/components/Button.tsx"}])
    );
    let all_paths: Vec<String> = with_files.data()["commits"]
        .as_array()
        .expect("commits")
        .iter()
        .flat_map(|c| strs(c, "files", "path"))
        .collect();
    assert!(
        !all_paths.iter().any(|p| p.starts_with(".env")),
        "denied paths leaked"
    );
    assert!(
        with_files.has_notice("output_truncated"),
        "50 files per commit cap"
    );

    let with_body = c
        .call(
            "log",
            json!({"repo": "web", "include_body": true, "max_count": 1}),
        )
        .await;
    assert!(with_body.ok()["commits"][0].get("body").is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn log_since_and_errors() {
    let c = default_server().full().await;
    let future = c
        .call("log", json!({"repo": "web", "since": "2999-01-01"}))
        .await;
    assert!(future.ok()["commits"].as_array().is_some_and(Vec::is_empty));
    let past = c
        .call(
            "log",
            json!({"repo": "web", "since": "2000-01-01T00:00:00Z"}),
        )
        .await;
    assert_eq!(past.ok()["commits"].as_array().map(Vec::len), Some(3));

    c.call("log", json!({"repo": "web", "since": "yesterday"}))
        .await
        .expect_error("invalid_argument");
    c.call("log", json!({"repo": "web", "max_count": 0}))
        .await
        .expect_error("invalid_argument");
    c.call("log", json!({"repo": "web", "max_count": 101}))
        .await
        .expect_error("invalid_argument");
    c.call("log", json!({"repo": "web", "path": ".env"}))
        .await
        .expect_error("path_denied");
    c.call("log", json!({"repo": "web", "path": "nope.txt"}))
        .await
        .expect_error("path_not_found");
    c.call("log", json!({"repo": "nosuch"}))
        .await
        .expect_error("unknown_repo");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_reports_shallow_history_boundary() {
    let c = tight_server().full().await;
    let r = c.call("log", json!({"repo": "web"})).await;
    let data = r.ok();
    assert_eq!(data["commits"].as_array().map(Vec::len), Some(1));
    assert_eq!(data["history_truncated"], true);
    assert!(r.has_notice("history_truncated"));
    assert_eq!(data["source"]["commit"], data["commits"][0]["commit"]);
    let repos = c.call("list_repos", json!({})).await;
    assert_eq!(repos.ok()["repos"][0]["history_depth"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn blame_attributes_lines_to_commits() {
    let s = feature_server();
    let c = s.full().await;
    let commits = &s.env.up.first_commits;
    let r = c
        .call(
            "blame",
            json!({"repo": "web", "path": "src/components/Button.tsx"}),
        )
        .await;
    let lines = r.ok()["lines"].as_array().expect("lines").clone();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0]["commit"], commits[0]);
    assert_eq!(lines[2]["commit"], commits[2]);
    assert_eq!(lines[1]["text"], "// BUTTON_MARKER");
    assert_eq!(lines[0]["author_name"], "Test");
    assert_eq!(lines[2]["line"], 3);

    let range = c
        .call("blame", json!({"repo": "web", "path": "src/components/Button.tsx", "start_line": 2, "end_line": 3}))
        .await;
    assert_eq!(range.ok()["lines"].as_array().map(Vec::len), Some(2));

    c.call(
        "blame",
        json!({"repo": "web", "path": "README.md", "start_line": 99, "end_line": 100}),
    )
    .await
    .expect_error("offset_out_of_range");
    c.call(
        "blame",
        json!({"repo": "web", "path": "README.md", "start_line": 5, "end_line": 2}),
    )
    .await
    .expect_error("invalid_argument");
    c.call(
        "blame",
        json!({"repo": "web", "path": "README.md", "start_line": 1, "end_line": 900}),
    )
    .await
    .expect_error("invalid_argument");
    c.call("blame", json!({"repo": "web", "path": ".env"}))
        .await
        .expect_error("path_denied");
    c.call("blame", json!({"repo": "web", "path": "src"}))
        .await
        .expect_error("not_a_file");
    c.call("blame", json!({"repo": "web", "path": "nope.txt"}))
        .await
        .expect_error("path_not_found");
    c.call("blame", json!({"repo": "nosuch", "path": "README.md"}))
        .await
        .expect_error("unknown_repo");
}

#[tokio::test(flavor = "multi_thread")]
async fn blame_is_invalid_when_the_feature_is_off() {
    let c = default_server().full().await;
    let r = c
        .call("blame", json!({"repo": "web", "path": "README.md"}))
        .await;
    r.expect_error("invalid_argument");
    assert!(
        r.error_message().contains("not enabled"),
        "{}",
        r.error_message()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_edge_auth_origin_size_and_probes() {
    let s = Server::start(&opts(|o| {
        o.failed_attempts =
            "max_failures = 5\nwindow = \"10m\"\nbase_backoff = \"1s\"\nmax_backoff = \"5s\""
                .into();
    }));
    let http = reqwest::Client::new();
    let url = s.mcp_url();
    let key = s.full_key();
    let public = format!("http://127.0.0.1:{}", s.port());
    let admin = format!("http://127.0.0.1:{}", s.admin_port());

    let healthz = http
        .get(format!("{public}/healthz"))
        .send()
        .await
        .expect("healthz");
    assert_eq!(healthz.status(), 200);
    assert_eq!(healthz.text().await.expect("body"), "ok");
    for path in ["/readyz", "/metrics"] {
        let r = http
            .get(format!("{public}{path}"))
            .send()
            .await
            .expect("public admin path");
        assert_eq!(r.status(), 404, "{path} must not be on the public port");
    }

    let ready = http
        .get(format!("{admin}/readyz"))
        .send()
        .await
        .expect("readyz");
    assert_eq!(ready.status(), 200);
    let body: Value = ready.json().await.expect("readyz json");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["keys"]["count"], 2);
    assert_eq!(body["repos"].as_array().map(Vec::len), Some(2));

    let ok = post(&http, &url, Some(key), &[], list_repos_call()).await;
    assert_eq!(ok.status(), 200);
    assert!(ok.headers().contains_key("x-request-id"));
    let metrics = http
        .get(format!("{admin}/metrics"))
        .send()
        .await
        .expect("metrics");
    assert_eq!(metrics.status(), 200);
    let text = metrics.text().await.expect("metrics body");
    assert!(text.contains("explorer_tool_calls_total"), "{text}");
    assert!(text.contains("list_repos"));

    let evil = post(
        &http,
        &url,
        Some(key),
        &[("Origin", "https://evil.example")],
        list_repos_call(),
    )
    .await;
    assert_eq!(evil.status(), 403);
    let huge = rpc(
        4,
        "tools/call",
        json!({"name": "grep", "arguments": {"pattern": "x".repeat(70 * 1024)}}),
    );
    let too_big = post(&http, &url, Some(key), &[], huge).await;
    assert_eq!(too_big.status(), 413);

    let mut wrong = key.to_owned();
    wrong.pop();
    wrong.push(if key.ends_with('A') { 'B' } else { 'A' });
    let none = post(&http, &url, None, &[], list_repos_call()).await;
    assert_eq!(none.status(), 401);
    let challenge = none
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(challenge.starts_with("Bearer"), "{challenge}");
    let bad = post(&http, &url, Some(&wrong), &[], list_repos_call()).await;
    assert_eq!(bad.status(), 401);
    assert!(bad.headers().contains_key("www-authenticate"));
    for garbage in ["garbage", "cex_aaaaaaaa_bbbb"] {
        let r = post(&http, &url, Some(garbage), &[], list_repos_call()).await;
        assert_eq!(r.status(), 401, "{garbage}");
    }
    let fifth = post(&http, &url, Some(&wrong), &[], list_repos_call()).await;
    assert_eq!(fifth.status(), 401);

    let blocked = post(&http, &url, Some(key), &[], list_repos_call()).await;
    assert_eq!(
        blocked.status(),
        429,
        "the right key is refused while the client is blocked"
    );
    let retry: u64 = blocked
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("Retry-After seconds");
    assert!(retry >= 1);
    let still_up = http
        .get(format!("{public}/healthz"))
        .send()
        .await
        .expect("healthz");
    assert_eq!(still_up.status(), 200);

    let start = Instant::now();
    loop {
        let r = post(&http, &url, Some(key), &[], list_repos_call()).await;
        if r.status() == 200 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "still blocked: {}",
            r.status()
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let metrics = http
        .get(format!("{admin}/metrics"))
        .send()
        .await
        .expect("metrics");
    let text = metrics.text().await.expect("metrics body");
    assert!(text.contains("explorer_auth_failures_total"));
}

#[tokio::test(flavor = "multi_thread")]
async fn key_changes_apply_without_restart() {
    let s = Server::start(&opts(|o| {
        o.failed_attempts = "max_failures = 1000".into();
    }));
    let keys = Keys::get();
    assert!(
        keys.full_table.contains("disabled = false"),
        "{}",
        keys.full_table
    );
    let http = reqwest::Client::new();
    let url = s.mcp_url();
    let full: &str = &keys.full;
    let scoped: &str = &keys.scoped;
    let status_of = |key: &str| {
        let (http, url, key) = (http.clone(), url.clone(), key.to_owned());
        async move {
            post(&http, &url, Some(&key), &[], list_repos_call())
                .await
                .status()
                .as_u16()
        }
    };
    let wait_status = |key: &str, want: u16, what: &'static str| {
        let check = status_of(key);
        let (http, url, key) = (http.clone(), url.clone(), key.to_owned());
        async move {
            let start = Instant::now();
            let mut last = check.await;
            while last != want {
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "{what}: no {want} within 3s"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                last = post(&http, &url, Some(&key), &[], list_repos_call())
                    .await
                    .status()
                    .as_u16();
            }
        }
    };

    assert_eq!(status_of(full).await, 200);
    let write = |text: String| std::fs::write(&s.env.keys_file, text).expect("write keys");

    write(format!(
        "{}\n\n{}\n",
        keys.full_table
            .replace("disabled = false", "disabled = true"),
        keys.scoped_table
    ));
    wait_status(full, 401, "disabled key").await;
    assert_eq!(status_of(scoped).await, 200);

    write(keys.keys_toml());
    wait_status(full, 200, "re-enabled key").await;

    write(format!("{}\n", keys.scoped_table));
    wait_status(full, 401, "deleted key").await;
    assert_eq!(status_of(scoped).await, 200);
    assert_eq!(s.readyz()["keys"]["count"], 1);

    write("this is not toml [".into());
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        status_of(scoped).await,
        200,
        "a broken keys file keeps the previous set"
    );
    assert!(s.readyz()["keys"]["reload_error"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn puller_serves_new_commits_then_goes_stale_when_the_remote_vanishes() {
    let s = Server::start(&opts(|o| {
        o.pull = "interval = \"30s\"\njitter = \"1s\"\nstale_after = \"40s\"".into();
    }));
    let c = s.full().await;
    let before = c.call("list_repos", json!({})).await;
    assert_eq!(before.ok()["repos"][0]["commit"], s.env.up.head());
    assert_eq!(before.data()["repos"][0]["status"], "ready");

    let new_commit = s.env.up.push_first(
        "docs/NEW_NOTE.md",
        "NEWFILE_MARKER\n",
        "Add a note upstream",
    );
    let start = Instant::now();
    loop {
        let r = c.call("list_repos", json!({})).await;
        if r.ok()["repos"][0]["commit"] == new_commit {
            assert_eq!(
                r.data()["repos"][0]["commit_subject"],
                "Add a note upstream"
            );
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "new commit not pulled in 45s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let read = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "docs/NEW_NOTE.md"}),
        )
        .await;
    assert_eq!(read.ok()["content"], "NEWFILE_MARKER");
    let found = c
        .call(
            "grep",
            json!({"repos": ["web"], "pattern": "NEWFILE_MARKER"}),
        )
        .await;
    assert_eq!(found.ok()["matches"][0]["path"], "docs/NEW_NOTE.md");
    let logged = c.call("log", json!({"repo": "web", "max_count": 1})).await;
    assert_eq!(logged.ok()["commits"][0]["commit"], new_commit);
    assert!(!read.has_notice("stale_snapshot"));

    let gone = s.env.up.first_bare.with_extension("gone");
    std::fs::rename(&s.env.up.first_bare, &gone).expect("hide remote");

    let start = Instant::now();
    let class = loop {
        let health = s.repo_health("web");
        if let Some(class) = health["last_error"]["class"].as_str() {
            assert!(health["consecutive_failures"].as_u64().unwrap_or(0) >= 1);
            break class.to_owned();
        }
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "no pull error reported in 45s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        ["network", "auth", "internal"].contains(&class.as_str()),
        "{class}"
    );
    assert_eq!(s.repo_health("other")["last_error"], Value::Null);

    let tree = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "docs/NEW_NOTE.md"}),
        )
        .await;
    assert_eq!(
        tree.ok()["content"],
        "NEWFILE_MARKER",
        "the last snapshot keeps being served"
    );

    let start = Instant::now();
    loop {
        let r = c.call("list_repos", json!({})).await;
        if r.ok()["repos"][0]["status"] == "stale" {
            assert!(r.has_notice("stale_snapshot"));
            assert!(r.data()["repos"][0]["stale_seconds"].as_u64().unwrap_or(0) >= 40);
            assert_eq!(r.data()["repos"][1]["status"], "ready");
            assert_eq!(r.data()["repos"][0]["commit"], new_commit);
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(40),
            "repo never became stale"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let stale_read = c
        .call("read_file", json!({"repo": "web", "path": "README.md"}))
        .await;
    assert!(stale_read.ok()["source"]["stale"] == true);
    assert!(stale_read.has_notice("stale_snapshot"));
    let stale_tree = c
        .call("list_tree", json!({"repo": "web", "depth": 1}))
        .await;
    assert!(stale_tree.has_notice("stale_snapshot"));
    let stale_grep = c.call("grep", json!({"pattern": "NEWFILE_MARKER"})).await;
    assert!(stale_grep.has_notice("stale_snapshot"));
    assert!(
        stale_grep
            .raw
            .to_string()
            .contains("web: No successful pull")
    );
    let fresh = c
        .call("read_file", json!({"repo": "other", "path": "notes.md"}))
        .await;
    assert!(!fresh.has_notice("stale_snapshot"));
    assert_eq!(s.readyz()["status"], "degraded");
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_policies_redact_warn_and_block() {
    let s = scan_server();
    let c = s.full().await;
    let secret = aws_secret();

    let repos = c.call("list_repos", json!({})).await;
    let by_id = |id: &str| {
        repos.data()["repos"]
            .as_array()
            .and_then(|r| r.iter().find(|x| x["id"] == id))
            .cloned()
            .expect("repo entry")
    };
    assert_eq!(by_id("web")["status"], "ready");
    assert_eq!(by_id("other")["status"], "ready");
    assert_eq!(by_id("web-warn")["status"], "ready");
    assert_eq!(by_id("web-warn")["secrets_redacted"], 1);
    assert_eq!(by_id("web-block")["status"], "unavailable");
    assert_eq!(by_id("web-block")["commit"], Value::Null);

    let redacted = c
        .call(
            "read_file",
            json!({"repo": "web", "path": "config/keys.txt"}),
        )
        .await;
    assert!(
        redacted.ok()["content"]
            .as_str()
            .unwrap_or_default()
            .contains("[REDACTED:aws-access-token]")
    );
    assert!(!redacted.raw.to_string().contains(&secret));

    let warned = c
        .call(
            "read_file",
            json!({"repo": "web-warn", "path": "config/keys.txt"}),
        )
        .await;
    assert!(
        warned.ok()["content"]
            .as_str()
            .unwrap_or_default()
            .contains(&secret)
    );
    assert!(!warned.has_notice("secrets_redacted"));

    let blocked = c
        .call(
            "read_file",
            json!({"repo": "web-block", "path": "README.md"}),
        )
        .await;
    blocked.expect_error("repo_not_ready");
    assert_eq!(blocked.data()["error"]["retryable"], true);
    c.call("list_tree", json!({"repo": "web-block"}))
        .await
        .expect_error("repo_not_ready");

    let only_blocked = c
        .call("grep", json!({"pattern": "Hello", "repos": ["web-block"]}))
        .await;
    only_blocked.expect_error("repo_not_ready");
    let mixed = c
        .call(
            "grep",
            json!({"pattern": "OTHER_MARKER", "repos": ["other", "web-block"]}),
        )
        .await;
    assert_eq!(strs(mixed.ok(), "matches", "repo"), ["other"]);
    assert_eq!(mixed.data()["repos_skipped"][0]["repo"], "web-block");
    assert_eq!(mixed.data()["repos_skipped"][0]["reason"], "repo_not_ready");

    let held = s.repo_health("web-block");
    assert_eq!(held["scan"]["held"], true);
    assert_eq!(held["scan"]["policy"], "block");
    assert_eq!(held["last_error"]["class"], "secret_found");
    assert_eq!(s.repo_health("web-warn")["scan"]["findings"], 1);
    assert_eq!(s.repo_health("web-warn")["scan"]["policy"], "warn");
    assert_eq!(s.repo_health("other")["status"], "ready");
    assert_eq!(s.readyz()["status"], "degraded");
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_greps_succeed_or_report_busy() {
    let c = tight_server().full().await;
    let calls = (0..20).map(|i| {
        let c = &c;
        async move {
            let pattern = if i % 2 == 0 { "e" } else { "Hello" };
            c.call("grep", json!({"pattern": pattern})).await
        }
    });
    let replies = futures::future::join_all(calls).await;
    let mut ok = 0;
    for r in &replies {
        if r.is_error() {
            assert_eq!(r.error_code(), Some("busy"), "{}", r.raw);
            assert_eq!(r.data()["error"]["retryable"], true);
        } else {
            ok += 1;
        }
    }
    assert!(ok >= 1, "at least one call must get a worker");
    let after = c.call("grep", json!({"pattern": "OTHER_MARKER"})).await;
    assert_eq!(
        strs(after.ok(), "matches", "repo"),
        ["other"],
        "workers are released after the burst"
    );
}
