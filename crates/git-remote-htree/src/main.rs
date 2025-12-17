//! Git remote helper for hashtree
//!
//! Usage:
//!   git remote add origin htree://<pubkey>/<repo-name>
//!   git remote add origin htree://<petname>/<repo-name>
//!   git push origin main
//!   git pull origin main
//!
//! The identifier can be:
//! - A 64-character hex pubkey
//! - An npub bech32 address
//! - A petname defined in ~/.hashtree/keys
//!
//! The helper implements the git remote helper protocol:
//! https://git-scm.com/docs/gitremote-helpers

use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};
use tracing::{debug, info, warn};

mod config;
mod helper;
mod nostr_client;

use config::load_config;
use helper::RemoteHelper;
use nostr_client::resolve_identity;

fn main() -> Result<()> {
    // Suppress broken pipe panics - git may close the pipe early
    // This is the standard solution for CLI tools that write to stdout
    #[cfg(unix)]
    {
        // Reset SIGPIPE to default (terminate) instead of panic
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    // Initialize logging - default to error, override with RUST_LOG=git_remote_htree=debug
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("git_remote_htree=error".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    debug!("git-remote-htree called with args: {:?}", args);

    // Git calls: git-remote-htree <remote-name> <url>
    if args.len() < 3 {
        bail!("Usage: git-remote-htree <remote-name> <url>");
    }

    let remote_name = &args[1];
    let url = &args[2];

    info!("Remote: {}, URL: {}", remote_name, url);

    // Parse URL: htree://<identifier>/<repo-name>
    let (identifier, repo_name) = parse_htree_url(url)?;
    debug!("Parsed identifier: {}, repo: {}", identifier, repo_name);

    // Resolve identifier to pubkey (and optionally secret key)
    let (pubkey, secret_key) = resolve_identity(&identifier)?;
    debug!("Resolved to pubkey: {}", pubkey);

    if secret_key.is_some() {
        debug!("Have signing key for this identity");
    } else {
        warn!("No signing key for {} - push will fail", identifier);
    }

    // Load config
    let config = load_config();
    debug!("Loaded config with {} read servers, {} write servers",
           config.blossom.read_servers.len(),
           config.blossom.write_servers.len());

    // Create helper and run protocol
    let mut helper = RemoteHelper::new(&pubkey, &repo_name, secret_key, config)?;

    // Read commands from stdin, write responses to stdout
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // EOF or pipe closed
        };
        let line = line.trim();

        debug!("Received command: '{}'", line);

        let response = helper.handle_command(line)?;
        if let Some(resp) = response {
            debug!("Sending response: {:?}", resp);
            for line in resp {
                // Ignore broken pipe errors - git may close the pipe early
                if writeln!(stdout, "{}", line).is_err() {
                    return Ok(());
                }
            }
            let _ = stdout.flush();
        }

        if helper.should_exit() {
            break;
        }
    }

    Ok(())
}

/// Parse htree URL into (identifier, repo_name)
/// Formats: htree://<identifier>/<repo> or htree:<identifier>/<repo>
/// Identifier can be: petname, npub, or hex pubkey
fn parse_htree_url(url: &str) -> Result<(String, String)> {
    let path = url
        .strip_prefix("htree://")
        .or_else(|| url.strip_prefix("htree:"))
        .context("URL must start with htree:// or htree:")?;

    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 {
        bail!("URL must be htree://<identifier>/<repo-name>");
    }

    let identifier = parts[0].to_string();
    let repo_name = parts[1].to_string();

    if identifier.is_empty() {
        bail!("Identifier cannot be empty");
    }

    Ok((identifier, repo_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_htree_url_pubkey() {
        let (id, repo) = parse_htree_url(
            "htree://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/myrepo",
        )
        .unwrap();
        assert_eq!(
            id,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "myrepo");
    }

    #[test]
    fn test_parse_htree_url_petname() {
        let (id, repo) = parse_htree_url("htree://work/myproject").unwrap();
        assert_eq!(id, "work");
        assert_eq!(repo, "myproject");
    }

    #[test]
    fn test_parse_htree_url_npub() {
        let (id, repo) = parse_htree_url(
            "htree://npub1g53znsnsmu4x0hfkx9e7cs4xtqxsazkyd5nd94u4qzr0gnfndj4q0gzn94/repo",
        )
        .unwrap();
        assert!(id.starts_with("npub1"));
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_htree_url_colon() {
        let (id, repo) = parse_htree_url("htree:default/test-repo").unwrap();
        assert_eq!(id, "default");
        assert_eq!(repo, "test-repo");
    }

    #[test]
    fn test_parse_htree_url_invalid_scheme() {
        assert!(parse_htree_url("https://github.com/foo/bar").is_err());
    }

    #[test]
    fn test_parse_htree_url_no_repo() {
        assert!(parse_htree_url("htree://work").is_err());
    }

    #[test]
    fn test_parse_htree_url_empty_identifier() {
        assert!(parse_htree_url("htree:///repo").is_err());
    }

    #[test]
    fn test_parse_htree_url_with_subpath() {
        let (id, repo) = parse_htree_url("htree://personal/org/repo").unwrap();
        assert_eq!(id, "personal");
        assert_eq!(repo, "org/repo");
    }
}
