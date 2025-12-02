//! Git remote helper for nostr
//!
//! Usage: git remote add nostr nostr://<pubkey>/<repo-name>
//!        git push nostr main
//!        git pull nostr main
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
                .add_directive("git_remote_nostr=debug".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    debug!("git-remote-nostr called with args: {:?}", args);

    // Git calls: git-remote-nostr <remote-name> <url>
    if args.len() < 3 {
        bail!("Usage: git-remote-nostr <remote-name> <url>");
    }

    let remote_name = &args[1];
    let url = &args[2];

    info!("Remote: {}, URL: {}", remote_name, url);

    // Parse URL: nostr://<pubkey>/<repo-name> or nostr:<pubkey>/<repo-name>
    let (pubkey, repo_name) = parse_nostr_url(url)?;
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

/// Parse nostr URL into (pubkey, repo_name)
/// Formats: nostr://<pubkey>/<repo> or nostr:<pubkey>/<repo>
fn parse_nostr_url(url: &str) -> Result<(String, String)> {
    let path = url
        .strip_prefix("nostr://")
        .or_else(|| url.strip_prefix("nostr:"))
        .context("URL must start with nostr:// or nostr:")?;

    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() != 2 {
        bail!("URL must be nostr://<pubkey>/<repo-name>");
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
    fn test_parse_nostr_url() {
        let (pk, repo) = parse_nostr_url(
            "nostr://4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/myrepo",
        )
        .unwrap();
        assert_eq!(
            pk,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "myrepo");
    }

    #[test]
    fn test_parse_nostr_url_colon() {
        let (pk, repo) = parse_nostr_url(
            "nostr:4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0/test-repo",
        )
        .unwrap();
        assert_eq!(
            pk,
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0"
        );
        assert_eq!(repo, "test-repo");
    }

    #[test]
    fn test_parse_nostr_url_invalid() {
        assert!(parse_nostr_url("https://github.com/foo/bar").is_err());
        assert!(parse_nostr_url("nostr://shortkey/repo").is_err());
    }
}
