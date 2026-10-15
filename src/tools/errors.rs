//! Typed tool errors: stable codes, `isError` results and the structured error body.

use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnknownRepo,
    PathNotFound,
    PathDenied,
    NotAFile,
    NotADirectory,
    BinaryFile,
    FileTooLarge,
    OffsetOutOfRange,
    InvalidPattern,
    PatternTooComplex,
    InvalidArgument,
    HistoryUnavailable,
    RepoNotReady,
    Timeout,
    Busy,
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::UnknownRepo => "unknown_repo",
            ErrorCode::PathNotFound => "path_not_found",
            ErrorCode::PathDenied => "path_denied",
            ErrorCode::NotAFile => "not_a_file",
            ErrorCode::NotADirectory => "not_a_directory",
            ErrorCode::BinaryFile => "binary_file",
            ErrorCode::FileTooLarge => "file_too_large",
            ErrorCode::OffsetOutOfRange => "offset_out_of_range",
            ErrorCode::InvalidPattern => "invalid_pattern",
            ErrorCode::PatternTooComplex => "pattern_too_complex",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::HistoryUnavailable => "history_unavailable",
            ErrorCode::RepoNotReady => "repo_not_ready",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Busy => "busy",
            ErrorCode::Internal => "internal",
        }
    }
}

const REQUEST_PLACEHOLDER: &str = "{request}";

#[derive(Debug, Clone)]
pub struct ToolError {
    pub code: ErrorCode,
    pub message: String,
    pub hint: Option<String>,
    pub retryable: bool,
    cause: Option<String>,
}

fn display_path(path: &str) -> &str {
    if path.is_empty() {
        "the repository root"
    } else {
        path
    }
}

impl ToolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ToolError {
            code,
            message: message.into(),
            hint: None,
            retryable: false,
            cause: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn unknown_repo(id: &str, visible: &[String]) -> Self {
        ToolError::new(
            ErrorCode::UnknownRepo,
            format!(
                "No repo \"{id}\". Your repos: {}. Call list_repos for descriptions.",
                visible.join(", ")
            ),
        )
    }

    pub fn path_not_found(
        path: &str,
        repo: &str,
        short_commit: &str,
        suggestions: &[String],
    ) -> Self {
        let mut message = format!("{} not found at {repo}@{short_commit}.", display_path(path));
        match suggestions {
            [] => {}
            [one] => message.push_str(&format!(" Did you mean {one}?")),
            many => message.push_str(&format!(" Did you mean one of: {}?", many.join(", "))),
        }
        let mut err = ToolError::new(ErrorCode::PathNotFound, message);
        if suggestions.is_empty() {
            err.hint = Some("Use list_tree or glob to find the file.".into());
        }
        err
    }

    pub fn path_denied(path: &str) -> Self {
        ToolError::new(
            ErrorCode::PathDenied,
            format!(
                "{} is blocked by the server's path policy. Do not retry; ask the operator if this is wrong.",
                display_path(path)
            ),
        )
    }

    pub fn not_a_file(path: &str) -> Self {
        ToolError::new(
            ErrorCode::NotAFile,
            format!(
                "{} is a directory. Use list_tree or glob.",
                display_path(path)
            ),
        )
    }

    pub fn not_a_directory(path: &str) -> Self {
        ToolError::new(
            ErrorCode::NotADirectory,
            format!("{path} is a file. Use read_file to read it."),
        )
    }

    pub fn binary_file(path: &str, size: u64) -> Self {
        ToolError::new(
            ErrorCode::BinaryFile,
            format!(
                "{path} is binary ({}); this server returns text only.",
                super::caps::human_size(size)
            ),
        )
    }

    pub fn file_too_large(path: &str, size: u64, limit: u64) -> Self {
        ToolError::new(
            ErrorCode::FileTooLarge,
            format!(
                "{path} is {} (limit {}). Use grep to find the lines you need.",
                super::caps::human_size(size),
                super::caps::human_size(limit)
            ),
        )
        .with_hint("grep accepts path and glob filters; read_file accepts offset and limit.")
    }

    pub fn offset_out_of_range(total_lines: usize, offset: usize) -> Self {
        ToolError::new(
            ErrorCode::OffsetOutOfRange,
            format!("File has {total_lines} lines; offset {offset} is past the end."),
        )
    }

    pub fn invalid_pattern(message: impl Into<String>) -> Self {
        ToolError::new(ErrorCode::InvalidPattern, message)
    }

    pub fn pattern_too_complex(message: impl Into<String>) -> Self {
        ToolError::new(ErrorCode::PatternTooComplex, message)
            .with_hint("Set fixed_strings: true or narrow the pattern.")
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        ToolError::new(ErrorCode::InvalidArgument, message)
    }

    pub fn history_unavailable(depth: u32, commit: &str) -> Self {
        ToolError::new(
            ErrorCode::HistoryUnavailable,
            format!("Only the last {depth} commits are kept; {commit} is older."),
        )
    }

    pub fn repo_not_ready(message: impl Into<String>) -> Self {
        ToolError::new(ErrorCode::RepoNotReady, message).retryable()
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        ToolError::new(ErrorCode::Timeout, message).retryable()
    }

    pub fn busy() -> Self {
        ToolError::new(
            ErrorCode::Busy,
            "Server is at capacity. Retry in a few seconds.",
        )
        .retryable()
    }

    /// The real cause is logged when the error becomes a result; the client only sees the request id.
    pub fn internal(cause: impl std::fmt::Display) -> Self {
        let mut err = ToolError::new(
            ErrorCode::Internal,
            format!(
                "Internal error (request {REQUEST_PLACEHOLDER}). The operator can look this id up."
            ),
        );
        err.cause = Some(cause.to_string());
        err
    }

    /// Renders the `isError` result; `request_id` fills the internal error message and the log line.
    pub fn into_result(self, request_id: &str) -> CallToolResult {
        let message = self.message.replace(REQUEST_PLACEHOLDER, request_id);
        if self.code == ErrorCode::Internal {
            tracing::error!(
                request_id,
                cause = self.cause.as_deref().unwrap_or("unknown"),
                "internal tool error"
            );
        }
        let mut text = format!("{}: {message}", self.code.as_str());
        if let Some(hint) = &self.hint {
            text.push('\n');
            text.push_str(hint);
        }
        let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
        result.structured_content = Some(json!({
            "error": {
                "code": self.code.as_str(),
                "message": message,
                "hint": self.hint,
                "retryable": self.retryable,
            }
        }));
        result
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ToolError {}
