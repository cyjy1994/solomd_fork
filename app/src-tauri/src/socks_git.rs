//! Windows libgit2 uses WinHTTP. Use Git's libcurl transport for SOCKS.
use base64::Engine;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(super) fn selected_proxy(remote: &str, saved: Option<&str>) -> Option<String> {
    if !cfg!(windows) || !remote.starts_with("https://") {
        return None;
    }
    // Explicit app settings take precedence over inherited environment settings.
    let proxy = saved.map(str::to_string).or_else(|| {
        ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
            .iter()
            .find_map(|key| std::env::var(key).ok().filter(|s| !s.is_empty()))
    })?;
    let scheme = reqwest::Url::parse(&proxy).ok()?.scheme().to_string();
    matches!(scheme.as_str(), "socks5" | "socks5h").then_some(proxy)
}

fn git_binary() -> PathBuf {
    // GUI apps may have an older PATH than a newly installed Git for Windows.
    for (key, suffix) in [
        ("ProgramFiles", "Git/cmd/git.exe"),
        ("LOCALAPPDATA", "Programs/Git/cmd/git.exe"),
        ("ProgramFiles(x86)", "Git/cmd/git.exe"),
    ] {
        if let Some(root) = std::env::var_os(key) {
            let path = PathBuf::from(root).join(suffix);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("git")
}

fn command(git: &Path, repo: &Path, remote: &str, token: &str, proxy: &str, operation: &str, refspec: &str) -> Result<(Command, String), String> {
    let parsed = reqwest::Url::parse(remote).map_err(|_| "Invalid Git remote URL")?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("SOCKS Git transport requires an HTTPS remote without embedded credentials".into());
    }
    let username = if parsed.host_str() == Some("gitee.com") {
        parsed.path_segments().and_then(|mut p| p.next()).unwrap_or("x-access-token")
    } else {
        "x-access-token"
    };
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
    let settings = [
        (format!("http.{remote}.proxy"), proxy.to_string()),
        ("http.extraHeader".to_string(), String::new()),
        (format!("http.{remote}.extraHeader"), format!("Authorization: Basic {auth}")),
        ("credential.helper".to_string(), String::new()),
        ("http.followRedirects".to_string(), "false".to_string()),
    ];
    let mut cmd = Command::new(git);
    // No secrets in argv, URLs, or persistent git configuration.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("GIT_TRACE") || name.starts_with("GIT_CONFIG") || name == "GIT_CURL_VERBOSE" {
            cmd.env_remove(key);
        }
    }
    cmd.env("GIT_CONFIG_COUNT", settings.len().to_string());
    for (i, (key, value)) in settings.iter().enumerate() {
        cmd.env(format!("GIT_CONFIG_KEY_{i}"), key);
        cmd.env(format!("GIT_CONFIG_VALUE_{i}"), value);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0").env("GCM_INTERACTIVE", "Never");
    // An explicit SOCKS proxy must not be bypassed by inherited NO_PROXY.
    cmd.env_remove("NO_PROXY").env_remove("no_proxy");
    cmd.arg("--git-dir").arg(repo);
    match operation {
        "push" => { cmd.args(["push", "--porcelain", "--no-verify"]); }
        "fetch" => { cmd.args(["fetch", "--no-recurse-submodules", "--tags"]); }
        _ => return Err("Unsupported Git transfer operation".into()),
    }
    cmd.arg("--").arg(remote).arg(refspec);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    Ok((cmd, auth))
}

pub(super) fn transfer(repo: &Path, remote: &str, token: &str, proxy: &str, operation: &str, refspec: &str) -> Result<(), String> {
    let (mut cmd, auth) = command(&git_binary(), repo, remote, token, proxy, operation, refspec)?;
    let output = cmd.output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "SOCKS5 push/pull requires Git for Windows. Install with: winget install --id Git.Git --exact; then restart SoloMD.".to_string()
        } else {
            format!("Cannot start Git for SOCKS5 transfer: {e}")
        }
    })?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = format!("{}\n{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout));
    for secret in [token, auth.as_str(), proxy] {
        if !secret.is_empty() { message = message.replace(secret, "[redacted]"); }
    }
    Err(format!("Git {operation} failed: {}", message.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_not_in_arguments_and_fetch_updates_tracking_ref() {
        let (cmd, _) = command(Path::new("git"), Path::new("C:/notes with spaces/.git"), "https://github.com/test/notes.git", "secret-token", "socks5h://127.0.0.1:1080", "fetch", "+refs/heads/main:refs/remotes/origin/main").unwrap();
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(!args.iter().any(|a| a.contains("secret-token")));
        assert_eq!(args[1], "C:/notes with spaces/.git");
        assert_eq!(args.last().unwrap(), "+refs/heads/main:refs/remotes/origin/main");
        assert!(args.iter().any(|a| a == "--no-recurse-submodules"));
        assert!(cmd.get_envs().any(|(k, v)| k == "GIT_CONFIG_VALUE_0" && v == Some(std::ffi::OsStr::new("socks5h://127.0.0.1:1080"))));
    }

    #[test]
    fn rejects_insecure_or_credential_bearing_remotes() {
        for remote in ["http://github.com/test/notes.git", "https://user:password@github.com/test/notes.git"] {
            assert!(command(Path::new("git"), Path::new("."), remote, "token", "socks5h://localhost:1080", "push", "main:main").is_err());
        }
    }

    #[test]
    fn local_remotes_do_not_use_external_socks_transport() {
        assert!(selected_proxy("file:///tmp/test.git", Some("socks5h://localhost:1080")).is_none());
    }
}
