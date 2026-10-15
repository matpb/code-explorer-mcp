//! Helper behind `GIT_ASKPASS`: answers git's credential prompts from files and env, never logging them.

use std::path::Path;
use std::process::ExitCode;

/// Answer for `prompt`, or `None` when the needed input is missing.
pub fn answer(prompt: &str, user: Option<&str>, secret_file: Option<&Path>) -> Option<String> {
    if prompt.starts_with("Username") {
        return user.map(str::to_owned);
    }
    let content = std::fs::read_to_string(secret_file?).ok()?;
    Some(content.trim().to_owned())
}

/// Prints the answer for git's prompt on stdout; exit 1 when it cannot be produced.
pub fn run(prompt: &str) -> ExitCode {
    let user = std::env::var("CODE_EXPLORER_ASKPASS_USER").ok();
    let file = std::env::var_os("CODE_EXPLORER_ASKPASS_FILE");
    match answer(prompt, user.as_deref(), file.as_deref().map(Path::new)) {
        Some(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        None => ExitCode::FAILURE,
    }
}

/// Call first in `main`: when git invoked this binary as its askpass helper (`exe <prompt>` with
/// `CODE_EXPLORER_ASKPASS_FILE` set, or `exe askpass <prompt>`), answers and returns the exit code.
pub fn try_handle() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, prompt] if cmd == "askpass" => Some(run(prompt)),
        [prompt]
            if is_git_prompt(prompt)
                && std::env::var_os("CODE_EXPLORER_ASKPASS_FILE").is_some() =>
        {
            Some(run(prompt))
        }
        _ => None,
    }
}

fn is_git_prompt(arg: &str) -> bool {
    arg.starts_with("Username") || arg.starts_with("Password")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn username_prompt_returns_user() {
        assert_eq!(
            answer("Username for 'https://example.com': ", Some("bob"), None),
            Some("bob".into())
        );
        assert_eq!(answer("Username for 'x': ", None, None), None);
    }

    #[test]
    fn password_prompt_returns_trimmed_file_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret");
        std::fs::write(&file, "  tok-123\n").unwrap();
        assert_eq!(
            answer(
                "Password for 'https://bob@example.com': ",
                Some("bob"),
                Some(&file)
            ),
            Some("tok-123".into())
        );
    }

    #[test]
    fn git_prompts_are_recognised() {
        assert!(is_git_prompt("Username for 'https://example.com': "));
        assert!(is_git_prompt("Password for 'https://bob@example.com': "));
        assert!(!is_git_prompt("serve"));
    }

    #[test]
    fn missing_file_fails() {
        assert_eq!(answer("Password for 'x': ", None, None), None);
        let missing = Path::new("/nonexistent/secret");
        assert_eq!(answer("Password for 'x': ", None, Some(missing)), None);
    }
}
