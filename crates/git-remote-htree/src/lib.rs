//! Git remote helper for hashtree
//!
//! This crate provides a git remote helper that allows pushing/pulling
//! git repositories via nostr and hashtree.
//!
//! ## Usage
//!
//! ```bash
//! git remote add origin htree://<pubkey>/<repo-name>
//! git remote add origin htree://<petname>/<repo-name>
//! git push origin main
//! git pull origin main
//! ```
//!
//! ## Encryption Modes
//!
//! - **Unencrypted**: No CHK, just hash - anyone with hash can read
//! - **Public**: CHK encrypted, `["key", "<hex>"]` in event - anyone can decrypt
//! - **Unlisted**: CHK + XOR mask, `["encryptedKey", XOR(key,secret)]` - need `#k=<secret>` URL
//! - **Private**: CHK + NIP-44 to self, `["selfEncryptedKey", "..."]` - author only
//!
//! Default is **Public** (CHK encrypted, key in nostr event).
//! Use `htree://npub/repo#k=<secret>` for unlisted/link-visible repos.

use anyhow::{bail, Context, Result};
use nostr_sdk::ToBech32;
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

    // Initialize logging - suppress nostr relay connection errors
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("git_remote_htree=warn".parse().unwrap())
                .add_directive("nostr_relay_pool=off".parse().unwrap()),
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

    // Parse URL: htree://<identifier>/<repo-name>#k=<secret>
    let parsed = parse_htree_url(url)?;
    let identifier = parsed.identifier;
    let repo_name = parsed.repo_name;
    let url_secret = parsed.secret_key; // Encryption secret from URL fragment

    if url_secret.is_some() {
        info!("Private repo mode: using secret key from URL");
    }

    // Resolve identifier to pubkey
    // If "self" is used and no keys exist, auto-generate
    let (pubkey, signing_key) = match resolve_identity(&identifier) {
        Ok(result) => result,
        Err(e) => {
            // If resolution failed and user intended "self", suggest using htree://self/repo
            warn!("Failed to resolve identity '{}': {}", identifier, e);
            info!("Tip: Use htree://self/<repo> to auto-generate identity on first use");
            return Err(e);
        }
    };

    if signing_key.is_some() {
        debug!("Found signing key for {}", identifier);
    } else {
        debug!("No signing key for {} (read-only)", identifier);
    }

    // Print npub for reference
    if let Ok(pk_bytes) = hex::decode(&pubkey) {
        if pk_bytes.len() == 32 {
            if let Ok(pk) = nostr_sdk::PublicKey::from_slice(&pk_bytes) {
                if let Ok(npub) = pk.to_bech32() {
                    info!("Using identity: {}", npub);
                }
            }
        }
    }

    // Load config
    let config = Config::load_or_default();
    debug!("Loaded config with {} read servers, {} write servers",
           config.blossom.read_servers.len(),
           config.blossom.write_servers.len());

    // Create helper and run protocol
    let mut helper = RemoteHelper::new(&pubkey, &repo_name, signing_key, url_secret, config)?;

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
                // Exit on error to avoid hanging
                return Err(e);
            }
        }

        if helper.should_exit() {
            break;
        }
    }

    Ok(())
}

/// Parsed htree URL components
pub struct ParsedUrl {
    pub identifier: String,
    pub repo_name: String,
    /// Secret key from #k=<hex> fragment (for private repos)
    pub secret_key: Option<[u8; 32]>,
}

/// Parse htree:// URL into components
/// Supports: htree://identifier/repo#k=<hex> for private repos
fn parse_htree_url(url: &str) -> Result<ParsedUrl> {
    let url = url
        .strip_prefix("htree://")
        .context("URL must start with htree://")?;

    // Split off fragment (#k=secret) if present
    let (url_path, secret_key) = if let Some((path, fragment)) = url.split_once('#') {
        let key = if let Some(key_hex) = fragment.strip_prefix("k=") {
            let bytes = hex::decode(key_hex)
                .context("Invalid secret key hex in URL fragment")?;
            if bytes.len() != 32 {
                bail!("Secret key must be 32 bytes (64 hex chars)");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        } else {
            None
        };
        (path, key)
    } else {
        (url, None)
    };

    // Split on first /
    let (identifier, repo) = url_path
        .split_once('/')
        .context("URL must be htree://<identifier>/<repo>")?;

    // Handle repo paths like "repo/subpath" - keep full path as repo name
    let repo_name = repo.to_string();

    if identifier.is_empty() {
        bail!("Identifier cannot be empty");
    }
    if repo_name.is_empty() {
        bail!("Repository name cannot be empty");
    }

    Ok(ParsedUrl {
        identifier: identifier.to_string(),
        repo_name,
        secret_key,
    })
}

/// Generate a new random secret key for private repos
pub fn generate_secret_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("Failed to generate random bytes");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_htree_url_pubkey() {
        let parsed = parse_htree_url(
            "htree://a9a91ed5f1c405618f63fdd393f9055ab8bac281102cff6b1ac3c74094562dd8/myrepo",
        )
        .unwrap();
        assert_eq!(
            parsed.identifier,
            "a9a91ed5f1c405618f63fdd393f9055ab8bac281102cff6b1ac3c74094562dd8"
        );
        assert_eq!(parsed.repo_name, "myrepo");
        assert!(parsed.secret_key.is_none());
    }

    #[test]
    fn test_parse_htree_url_npub() {
        let parsed =
            parse_htree_url("htree://npub1qvmu0aru530g6yu3kmlhw33fh68r75wf3wuml3vk4ekg0p4m4t6s7fuhxx/test")
                .unwrap();
        assert!(parsed.identifier.starts_with("npub1"));
        assert_eq!(parsed.repo_name, "test");
        assert!(parsed.secret_key.is_none());
    }

    #[test]
    fn test_parse_htree_url_petname() {
        let parsed = parse_htree_url("htree://alice/project").unwrap();
        assert_eq!(parsed.identifier, "alice");
        assert_eq!(parsed.repo_name, "project");
        assert!(parsed.secret_key.is_none());
    }

    #[test]
    fn test_parse_htree_url_self() {
        let parsed = parse_htree_url("htree://self/myrepo").unwrap();
        assert_eq!(parsed.identifier, "self");
        assert_eq!(parsed.repo_name, "myrepo");
        assert!(parsed.secret_key.is_none());
    }

    #[test]
    fn test_parse_htree_url_with_subpath() {
        let parsed = parse_htree_url("htree://test/repo/some/path").unwrap();
        assert_eq!(parsed.identifier, "test");
        assert_eq!(parsed.repo_name, "repo/some/path");
        assert!(parsed.secret_key.is_none());
    }

    #[test]
    fn test_parse_htree_url_with_secret() {
        let secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let url = format!("htree://test/repo#k={}", secret_hex);
        let parsed = parse_htree_url(&url).unwrap();
        assert_eq!(parsed.identifier, "test");
        assert_eq!(parsed.repo_name, "repo");
        assert!(parsed.secret_key.is_some());
        let key = parsed.secret_key.unwrap();
        assert_eq!(hex::encode(key), secret_hex);
    }

    #[test]
    fn test_parse_htree_url_invalid_secret_length() {
        // Secret too short
        let url = "htree://test/repo#k=0123456789abcdef";
        assert!(parse_htree_url(url).is_err());
    }

    #[test]
    fn test_parse_htree_url_invalid_secret_hex() {
        // Invalid hex characters
        let url = "htree://test/repo#k=ghij456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(parse_htree_url(url).is_err());
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
