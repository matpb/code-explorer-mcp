//! Subprocess runner: scrubbed environment, process-group kill on timeout, capped output.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Captured stdout is cut at this many bytes.
pub const STDOUT_CAP: usize = 64 * 1024 * 1024;
/// Captured stderr is cut at this many bytes.
pub const STDERR_CAP: usize = 64 * 1024;
/// Stderr carried inside `ProcError::Failed` is cut at this many bytes.
pub const FAILED_STDERR_CAP: usize = 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProcError {
    #[error("{kind} timed out after {after:?}")]
    Timeout { kind: &'static str, after: Duration },
    #[error("all workers are busy")]
    Busy,
    #[error("failed to spawn process: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("{kind} exited with status {status}: {stderr}")]
    Failed {
        kind: &'static str,
        status: i32,
        stderr: String,
    },
}

/// Result of a successful (exit 0) process run.
#[derive(Debug, Clone)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

/// Bounded pool of subprocess slots shared by every tool call.
#[derive(Debug)]
pub struct Workers {
    sem: Arc<Semaphore>,
    max: usize,
    queue_timeout: Duration,
}

/// Holds a worker slot until dropped.
#[derive(Debug)]
pub struct Permit {
    _permit: OwnedSemaphorePermit,
}

impl Workers {
    pub fn new(max_concurrent: usize, queue_timeout: Duration) -> Arc<Workers> {
        Arc::new(Workers {
            sem: Arc::new(Semaphore::new(max_concurrent)),
            max: max_concurrent,
            queue_timeout,
        })
    }

    pub async fn acquire(&self) -> Result<Permit, ProcError> {
        match tokio::time::timeout(self.queue_timeout, self.sem.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(Permit { _permit: permit }),
            _ => Err(ProcError::Busy),
        }
    }

    /// Number of slots currently held.
    pub fn busy(&self) -> usize {
        self.max.saturating_sub(self.sem.available_permits())
    }
}

const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

fn private_home() -> &'static PathBuf {
    static HOME: OnceLock<(Option<TempDir>, PathBuf)> = OnceLock::new();
    let (_, path) =
        HOME.get_or_init(
            || match tempfile::Builder::new().prefix("cex-home-").tempdir() {
                Ok(dir) => {
                    let path = dir.path().to_path_buf();
                    (Some(dir), path)
                }
                Err(_) => (None, PathBuf::from("/nonexistent")),
            },
        );
    path
}

/// Command with an empty environment plus a fixed safe set, its own process group and kill-on-drop.
pub fn scrubbed_command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    let path = std::env::var_os("PATH")
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| DEFAULT_PATH.into());
    cmd.env_clear()
        .env("PATH", path)
        .env("HOME", private_home())
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .process_group(0)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Runs `cmd` with null stdin. Non-zero exit is `ProcError::Failed`.
pub async fn run(cmd: Command, timeout: Duration, kind: &'static str) -> Result<Output, ProcError> {
    run_inner(cmd, timeout, kind, None).await
}

/// Like `run`, feeding `stdin` to the child.
pub async fn run_with_stdin(
    cmd: Command,
    timeout: Duration,
    kind: &'static str,
    stdin: Vec<u8>,
) -> Result<Output, ProcError> {
    run_inner(cmd, timeout, kind, Some(stdin)).await
}

/// Reads up to `cap` bytes, then drains the rest so the child never blocks on a full pipe.
async fn read_capped<R: AsyncRead + Unpin>(reader: Option<R>, cap: usize) -> (Vec<u8>, bool) {
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut buf = Vec::new();
    let mut limited = (&mut reader).take(cap as u64);
    if limited.read_to_end(&mut buf).await.is_err() {
        return (buf, false);
    }
    let mut probe = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut probe).await {
            Ok(0) | Err(_) => break,
            Ok(_) => truncated = true,
        }
    }
    (buf, truncated)
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        _ => -1,
    }
}

fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

async fn run_inner(
    mut cmd: Command,
    timeout: Duration,
    kind: &'static str,
    stdin: Option<Vec<u8>>,
) -> Result<Output, ProcError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = cmd.spawn().map_err(ProcError::Spawn)?;
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdin_pipe = child.stdin.take();

    let work = async {
        let feed = async {
            if let (Some(mut pipe), Some(data)) = (stdin_pipe, stdin) {
                let _ = pipe.write_all(&data).await;
                let _ = pipe.shutdown().await;
            }
        };
        let (_, out, err, status) = tokio::join!(
            feed,
            read_capped(stdout, STDOUT_CAP),
            read_capped(stderr, STDERR_CAP),
            child.wait()
        );
        (out, err, status)
    };

    match tokio::time::timeout(timeout, work).await {
        Err(_) => {
            kill_group(pid);
            let _ = child.wait().await;
            Err(ProcError::Timeout {
                kind,
                after: timeout,
            })
        }
        Ok(((stdout, stdout_truncated), (stderr, stderr_truncated), status)) => {
            let status = status.map_err(ProcError::Spawn)?;
            if status.success() {
                Ok(Output {
                    stdout,
                    stderr,
                    stdout_truncated,
                    stderr_truncated,
                })
            } else {
                let cut = &stderr[..stderr.len().min(FAILED_STDERR_CAP)];
                Err(ProcError::Failed {
                    kind,
                    status: exit_code(status),
                    stderr: String::from_utf8_lossy(cut).into_owned(),
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn pid_gone(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit(')')
                .next()
                .map(|rest| rest.trim_start().starts_with('Z'))
                .unwrap_or(false),
        }
    }

    async fn wait_gone(pid: u32) -> bool {
        for _ in 0..40 {
            if pid_gone(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn timeout_kills_child_fast() {
        let pid_dir = tempfile::tempdir().unwrap();
        let pid_file = pid_dir.path().join("pid");
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c")
            .arg(format!("echo $$ > {}; exec sleep 10", pid_file.display()));
        let start = Instant::now();
        let err = run(cmd, Duration::from_millis(200), "sleep")
            .await
            .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(matches!(err, ProcError::Timeout { kind: "sleep", .. }));
        let pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(wait_gone(pid).await, "child {pid} still alive");
    }

    #[tokio::test]
    async fn timeout_kills_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("grandchild");
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c")
            .arg(format!("sleep 30 & echo $! > {}; wait", pid_file.display()));
        let start = Instant::now();
        let err = run(cmd, Duration::from_millis(500), "group")
            .await
            .unwrap_err();
        assert!(matches!(err, ProcError::Timeout { .. }));
        assert!(start.elapsed() < Duration::from_secs(5));
        let pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(wait_gone(pid).await, "grandchild {pid} still alive");
    }

    #[tokio::test]
    async fn workers_busy_when_exhausted() {
        let workers = Workers::new(1, Duration::from_millis(100));
        let first = workers.acquire().await.unwrap();
        assert_eq!(workers.busy(), 1);
        assert!(matches!(workers.acquire().await, Err(ProcError::Busy)));
        drop(first);
        assert_eq!(workers.busy(), 0);
        assert!(workers.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn env_is_scrubbed() {
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c").arg("env");
        let out = run(cmd, Duration::from_secs(5), "env").await.unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        // cargo always exports CARGO* to the test process; none may reach the child.
        assert!(std::env::vars().any(|(k, _)| k.starts_with("CARGO")));
        assert!(!text.contains("CARGO"), "parent env leaked: {text}");
        assert!(!text.contains("CODE_EXPLORER_TEST_LEAK"));
        for expected in [
            "LC_ALL=C",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_LFS_SKIP_SMUDGE=1",
            "HOME=",
            "PATH=",
        ] {
            assert!(text.contains(expected), "missing {expected} in {text}");
        }
    }

    #[tokio::test]
    async fn failed_carries_status_and_stderr() {
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c").arg("echo boom >&2; exit 3");
        match run(cmd, Duration::from_secs(5), "fail").await {
            Err(ProcError::Failed {
                kind,
                status,
                stderr,
            }) => {
                assert_eq!(kind, "fail");
                assert_eq!(status, 3);
                assert!(stderr.contains("boom"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_stderr_truncated_to_4k() {
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c")
            .arg("head -c 20000 /dev/zero | tr '\\0' 'x' >&2; exit 1");
        match run(cmd, Duration::from_secs(5), "big").await {
            Err(ProcError::Failed { stderr, .. }) => assert_eq!(stderr.len(), FAILED_STDERR_CAP),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn stdout_cap_and_drain_do_not_hang() {
        let mut cmd = scrubbed_command("sh");
        cmd.arg("-c").arg("head -c 70000 /dev/zero >&2; echo ok");
        let out = run(cmd, Duration::from_secs(5), "cap").await.unwrap();
        assert_eq!(out.stdout, b"ok\n");
        assert_eq!(out.stderr.len(), STDERR_CAP);
        assert!(out.stderr_truncated);
        assert!(!out.stdout_truncated);
    }

    #[tokio::test]
    async fn stdin_is_delivered() {
        let cmd = scrubbed_command("cat");
        let out = run_with_stdin(cmd, Duration::from_secs(5), "cat", b"hello".to_vec())
            .await
            .unwrap();
        assert_eq!(out.stdout, b"hello");
    }

    #[tokio::test]
    async fn spawn_error_is_reported() {
        let cmd = scrubbed_command("/nonexistent/binary-xyz");
        assert!(matches!(
            run(cmd, Duration::from_secs(1), "x").await,
            Err(ProcError::Spawn(_))
        ));
    }
}
