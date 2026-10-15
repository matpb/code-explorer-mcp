use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    code_explorer_mcp::cli::run().await
}
