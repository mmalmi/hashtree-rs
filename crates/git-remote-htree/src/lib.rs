//! Git remote helper for hashtree
//!
//! This crate provides a git remote helper that allows pushing/pulling
//! git repositories via nostr and hashtree.
//!
//! Usage:
//!   git remote add origin htree://<pubkey>/<repo-name>
//!   git remote add origin htree://<petname>/<repo-name>
//!   git push origin main
//!   git pull origin main

use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};
use tracing::{debug, info, warn};

mod git;
mod helper;
mod nostr_client;

use hashtree_config::Config;
use helper::RemoteHelper;
use nostr_client::resolve_identity;

/// Entry point for the git remote helper
/// Call this from main() to run the helper
pub fn main_entry() {
    // Install TLS crypto provider for reqwest/rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // Suppress broken pipe panics - git may close the pipe early
    #[cfg(unix)]
    {
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("git_remote_htree=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().collect();
    debug!("git-remote-htree called with args: {:?}", args);

    // Git calls us as: git-remote-htree <remote-name> <url>
    if args.len() < 3 {
        bail!("Usage: git-remote-htree <remote-name> <url>");
    }

    let remote_name = &args[1];
    let url = &args[2];

    info!("Remote: {}, URL: {}", remote_name, url);

    // Parse URL: htree://<identifier>/<repo-name>
    let (identifier, repo_name) = parse_htree_url(url)?;

    // Resolve identifier to pubkey
    let (pubkey, secret_key) = resolve_identity(&identifier)?;

    if secret_key.is_some() {
        debug!("Found signing key for {}", identifier);
    } else {
        warn!("No signing key for {} - push will fail", identifier);
    }

    // Load config
    let config = Config::load_or_default();
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
            Err(e) => {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    break;
                }
                return Err(e.into());
            }
        };

        debug!("< {}", line);

        match helper.handle_command(&line) {
            Ok(Some(responses)) => {
                for response in responses {
                    debug!("> {}", response);
                    if let Err(e) = writeln!(stdout, "{}", response) {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            break;
                        }
                        return Err(e.into());
                    }
                }
                if let Err(e) = stdout.flush() {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        break;
                    }
                    return Err(e.into());
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Command error: {}", e);
            }
        }

        if helper.should_exit() {
            break;
        }
    }

    Ok(())
}

/// Parse htree:// URL into (identifier, repo_name)
fn parse_htree_url(url: &str) -> Result<(String, String)> {
    let url = url
        .strip_prefix("htree://")
        .context("URL must start with htree://")?;

    // Split on first /
    let (identifier, repo) = url
        .split_once('/')
        .context("URL must be htree://<identifier>/<repo>")?;

    // Handle repo paths like "repo/subpath" - just take the first component as repo name
    let repo_name = repo.split('/').next().unwrap_or(repo);

    if identifier.is_empty() {
        bail!("Identifier cannot be empty");
    }
    if repo_name.is_empty() {
        bail!("Repository name cannot be empty");
    }

    Ok((identifier.to_string(), repo_name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_htree_url_pubkey() {
        let (id, repo) = parse_htree_url(
            "htree://a9a91ed5f1c405618f63fdd393f9055ab8bac281102cff6b1ac3c74094562dd8/myrepo",
        )
        .unwrap();
        assert_eq!(
            id,
            "a9a91ed5f1c405618f63fdd393f9055ab8bac281102cff6b1ac3c74094562dd8"
        );
        assert_eq!(repo, "myrepo");
    }

    #[test]
    fn test_parse_htree_url_npub() {
        let (id, repo) =
            parse_htree_url("htree://npub1qvmu0aru530g6yu3kmlhw33fh68r75wf3wuml3vk4ekg0p4m4t6s7fuhxx/test")
                .unwrap();
        assert!(id.starts_with("npub1"));
        assert_eq!(repo, "test");
    }

    #[test]
    fn test_parse_htree_url_petname() {
        let (id, repo) = parse_htree_url("htree://alice/project").unwrap();
        assert_eq!(id, "alice");
        assert_eq!(repo, "project");
    }

    #[test]
    fn test_parse_htree_url_with_subpath() {
        let (id, repo) = parse_htree_url("htree://test/repo/some/path").unwrap();
        assert_eq!(id, "test");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_htree_url_invalid_scheme() {
        assert!(parse_htree_url("https://example.com/repo").is_err());
    }

    #[test]
    fn test_parse_htree_url_no_repo() {
        assert!(parse_htree_url("htree://pubkey").is_err());
    }

    #[test]
    fn test_parse_htree_url_empty_identifier() {
        assert!(parse_htree_url("htree:///repo").is_err());
    }

    #[test]
    fn test_parse_htree_url_colon() {
        // Some git versions may pass URL with : instead of /
        let result = parse_htree_url("htree://test:repo");
        assert!(result.is_err()); // We don't support : syntax
    }
}
