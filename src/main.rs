use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    if let Some(code) = code_explorer_mcp::git::askpass::try_handle() {
        return code;
    }
    code_explorer_mcp::cli::run().await
}
