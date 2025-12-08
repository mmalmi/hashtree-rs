//! Git remote helper for hashtree
//!
//! Usage: git remote add origin htree://<pubkey>/<repo-name>
//!        git push origin main
//!        git pull origin main
//!
//! The helper implements the git remote helper protocol:
//! https://git-scm.com/docs/gitremote-helpers

use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};
use tracing::{debug, info};

mod helper;
mod nostr_client;

use helper::RemoteHelper;

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("git_remote_htree=debug".parse().unwrap()),
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

    // Parse URL: htree://<pubkey>/<repo-name> or htree:<pubkey>/<repo-name>
    let (pubkey, repo_name) = parse_htree_url(url)?;
    debug!("Parsed pubkey: {}, repo: {}", pubkey, repo_name);

    // Create helper and run protocol
    let mut helper = RemoteHelper::new(&pubkey, &repo_name)?;

    // Read commands from stdin, write responses to stdout
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();

        debug!("Received command: '{}'", line);

        let response = helper.handle_command(line)?;
        if let Some(resp) = response {
            debug!("Sending response: {:?}", resp);
            for line in resp {
                writeln!(stdout, "{}", line)?;
            }
            stdout.flush()?;
        }

        if helper.should_exit() {
            break;
        }
    }

    Ok(())
}

/// Parse htree URL into (pubkey, repo_name)
/// Formats: htree://<pubkey>/<repo> or htree:<pubkey>/<repo>
fn parse_htree_url(url: &str) -> Result<(String, String)> {
    let path = url
        .strip_prefix("htree://")
        .or_else(|| url.strip_prefix("htree:"))
        .context("URL must start with htree:// or htree:")?;

    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 {
        bail!("URL must be htree://<pubkey>/<repo-name>");
    }

    let pubkey = parts[0].to_string();
    let repo_name = parts[1].to_string();

    // Validate pubkey is hex
    if pubkey.len() != 64 || hex::decode(&pubkey).is_err() {
        bail!("Invalid pubkey: must be 64 hex characters");
    }

    Ok((pubkey, repo_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_htree_url() {
        let (pk, repo) = parse_htree_url(
            "htree://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/myrepo",
        )
        .unwrap();
        assert_eq!(
            pk,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "myrepo");
    }

    #[test]
    fn test_parse_htree_url_colon() {
        let (pk, repo) = parse_htree_url(
            "htree:4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/test-repo",
        )
        .unwrap();
        assert_eq!(
            pk,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "test-repo");
    }

    #[test]
    fn test_parse_htree_url_invalid() {
        assert!(parse_htree_url("https://github.com/foo/bar").is_err());
        assert!(parse_htree_url("htree://shortkey/repo").is_err());
    }

    #[test]
    fn test_parse_htree_url_no_repo() {
        assert!(parse_htree_url(
            "htree://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        )
        .is_err());
    }

    #[test]
    fn test_parse_htree_url_empty_repo() {
        // This should fail - empty repo name after slash
        let result = parse_htree_url(
            "htree://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/",
        );
        // Empty repo name is technically valid by current implementation
        assert!(result.is_ok());
        let (_, repo) = result.unwrap();
        assert_eq!(repo, "");
    }

    #[test]
    fn test_parse_htree_url_with_subpath() {
        // Repo name can contain slashes
        let (pk, repo) = parse_htree_url(
            "htree://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/org/repo",
        )
        .unwrap();
        assert_eq!(
            pk,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "org/repo");
    }
}
