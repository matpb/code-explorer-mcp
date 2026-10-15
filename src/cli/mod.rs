//! Command line entry point. See docs/ARCHITECTURE.md.

mod check;
mod client;
mod keygen;
mod scan;
mod serve;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::{ALLOW_LOCAL_REMOTES_ENV, Config, LogFormat, Problem};
use crate::git::{self, GitRunner, GitTimeouts};

pub(crate) const EXIT_FAILURE: u8 = 1;
pub(crate) const EXIT_USAGE: u8 = 2;
pub(crate) const EXIT_FINDINGS: u8 = 3;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogFormatArg {
    Json,
    Pretty,
}

impl From<LogFormatArg> for LogFormat {
    fn from(f: LogFormatArg) -> Self {
        match f {
            LogFormatArg::Json => LogFormat::Json,
            LogFormatArg::Pretty => LogFormat::Pretty,
        }
    }
}

/// Read-only MCP server that lets AI agents explore GitHub and Bitbucket repositories.
#[derive(Debug, Parser)]
#[command(name = "code-explorer", version)]
struct Cli {
    /// Path to config.toml
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        env = "CODE_EXPLORER_CONFIG",
        default_value = "/etc/code-explorer/config.toml"
    )]
    config: PathBuf,

    /// Overrides [logging] format for `serve`
    #[arg(long, global = true, value_enum, value_name = "FORMAT")]
    log_format: Option<LogFormatArg>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (the default)
    Serve,
    /// Validate the config and the keys file, optionally probing every repo
    CheckConfig {
        /// Run `git ls-remote` against every repo with its credential
        #[arg(long)]
        probe: bool,
    },
    /// Generate a bearer key and append its hash to the keys file
    Keygen {
        /// Human-readable key name, unique within the keys file
        #[arg(long)]
        name: String,
        /// Comma-separated repo ids the key may see (default: all repos)
        #[arg(long, value_delimiter = ',', value_name = "IDS")]
        repos: Option<Vec<String>>,
        /// Expiry date, YYYY-MM-DD
        #[arg(long, value_name = "DATE")]
        expires: Option<NaiveDate>,
        /// Print the [[key]] block instead of appending it to the keys file
        #[arg(long)]
        print_only: bool,
    },
    /// Clone a configured repo, scan it for secrets and print the masked findings
    Scan {
        /// Repo id from the config
        #[arg(long)]
        repo: String,
    },
    /// Ask a running server for its /readyz report
    Status,
    /// Exit 0 when the running server answers /healthz (used by the container healthcheck)
    Healthcheck,
    #[command(hide = true)]
    Askpass { prompt: String },
}

pub async fn run() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve::run(&cli.config, cli.log_format.map(Into::into)).await,
        Command::CheckConfig { probe } => check::run(&cli.config, probe).await,
        Command::Keygen {
            name,
            repos,
            expires,
            print_only,
        } => keygen::run(&cli.config, &name, repos, expires, print_only),
        Command::Scan { repo } => scan::run(&cli.config, &repo).await,
        Command::Status => client::status(&cli.config).await,
        Command::Healthcheck => client::healthcheck(&cli.config).await,
        Command::Askpass { prompt } => return git::askpass::run(&prompt),
    };
    ExitCode::from(code)
}

/// Prints fatal problems as they are and warnings with a `warning:` prefix; returns the fatal count.
pub(crate) fn print_problems(problems: &[Problem]) -> usize {
    for p in problems {
        if p.fatal {
            eprintln!("{p}");
        } else {
            eprintln!("warning: {p}");
        }
    }
    problems.iter().filter(|p| p.fatal).count()
}

/// Parses and fully validates the config, printing every problem and warning.
pub(crate) fn load_validated(path: &Path) -> Result<Config, u8> {
    match Config::load(path) {
        Ok(loaded) => {
            print_problems(&loaded.warnings);
            Ok(loaded.config)
        }
        Err(problems) => {
            print_problems(&problems.0);
            Err(EXIT_USAGE)
        }
    }
}

/// Parses the config without filesystem or environment checks, for commands that need a few fields.
pub(crate) fn load_lenient(path: &Path) -> Result<Config, u8> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("{}: cannot read config file: {e}", path.display());
        EXIT_USAGE
    })?;
    Config::parse_unvalidated(&text, path).map_err(|problems| {
        print_problems(&problems.0);
        EXIT_USAGE
    })
}

pub(crate) fn git_runner(cfg: &Config) -> GitRunner {
    let allow_local = std::env::var(ALLOW_LOCAL_REMOTES_ENV).is_ok_and(|v| v == "1");
    GitRunner::new(
        cfg.git_bin(),
        GitTimeouts {
            fetch: cfg.pull.fetch_timeout,
            clone: cfg.pull.clone_timeout,
            command: cfg.limits.git_timeout,
        },
        cfg.pull.known_hosts_file.clone(),
        git::empty_hooks_dir(),
        allow_local,
    )
}
