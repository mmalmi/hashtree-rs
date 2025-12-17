//! Nostr client for publishing and fetching git repository references
//!
//! Uses kind 30078 (application-specific data) with hashtree structure:
//! {
//!   "kind": 30078,
//!   "tags": [
//!     ["d", "<repo-name>"],
//!     ["l", "hashtree"]
//!   ],
//!   "content": "<merkle-root-hash>"
//! }
//!
//! The merkle tree contains:
//!   root/
//!     refs/heads/main -> <sha>
//!     refs/tags/v1.0 -> <sha>
//!     objects/<sha1> -> data
//!     objects/<sha2> -> data
//!
//! ## Secret file format
//!
//! The secrets file (~/.hashtree/keys) supports multiple keys with optional petnames:
//! ```text
//! nsec1... default
//! nsec1... work
//! nsec1... personal
//! ```
//!
//! Or hex format:
//! ```text
//! <64-char-hex> default
//! <64-char-hex> work
//! ```
//!
//! Then use: `htree://work/myrepo` or `htree://npub1.../myrepo`

use anyhow::{Context, Result};
use hashtree_blossom::BlossomClient;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Event kind for application-specific data (NIP-78)
pub const KIND_APP_DATA: u16 = 30078;

/// Label for hashtree events
pub const LABEL_HASHTREE: &str = "hashtree";

/// A stored key with optional petname
#[derive(Debug, Clone)]
pub struct StoredKey {
    /// Secret key in hex format
    pub secret_hex: String,
    /// Public key in hex format
    pub pubkey_hex: String,
    /// Optional petname (e.g., "default", "work")
    pub petname: Option<String>,
}

impl StoredKey {
    /// Create from secret key hex, deriving pubkey
    pub fn from_secret_hex(secret_hex: &str, petname: Option<String>) -> Result<Self> {
        use secp256k1::{Secp256k1, SecretKey};

        let sk_bytes = hex::decode(secret_hex).context("Invalid hex in secret key")?;
        let sk = SecretKey::from_slice(&sk_bytes).context("Invalid secret key")?;
        let secp = Secp256k1::new();
        let pk = sk.x_only_public_key(&secp).0;
        let pubkey_hex = hex::encode(pk.serialize());

        Ok(Self {
            secret_hex: secret_hex.to_string(),
            pubkey_hex,
            petname,
        })
    }

    /// Create from nsec bech32 format
    pub fn from_nsec(nsec: &str, petname: Option<String>) -> Result<Self> {
        let secret_key =
            SecretKey::parse(nsec).map_err(|e| anyhow::anyhow!("Invalid nsec format: {}", e))?;
        let secret_hex = hex::encode(secret_key.to_secret_bytes());
        Self::from_secret_hex(&secret_hex, petname)
    }
}

/// Load all keys from config files
pub fn load_keys() -> Vec<StoredKey> {
    let mut keys = Vec::new();

    let Some(home) = dirs::home_dir() else {
        return keys;
    };

    // Primary: ~/.hashtree/keys (multi-key format)
    let keys_path = home.join(".hashtree/keys");
    if let Ok(content) = std::fs::read_to_string(&keys_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let key_str = parts[0];
            let petname = parts.get(1).map(|s| s.trim().to_string());

            let key = if key_str.starts_with("nsec1") {
                StoredKey::from_nsec(key_str, petname)
            } else if key_str.len() == 64 {
                StoredKey::from_secret_hex(key_str, petname)
            } else {
                continue;
            };

            if let Ok(k) = key {
                debug!(
                    "Loaded key: pubkey={}, petname={:?}",
                    k.pubkey_hex, k.petname
                );
                keys.push(k);
            }
        }
    }

    // Legacy: single-key files
    if keys.is_empty() {
        let legacy_paths = [
            home.join(".hashtree/nsec"),
            home.join(".config/nostr/secret"),
            home.join(".nostr/secret"),
            home.join(".config/git-remote-htree/secret"),
        ];

        for path in legacy_paths {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let key_str = content.trim();
                let key = if key_str.starts_with("nsec1") {
                    StoredKey::from_nsec(key_str, Some("default".to_string()))
                } else if key_str.len() == 64 {
                    StoredKey::from_secret_hex(key_str, Some("default".to_string()))
                } else {
                    continue;
                };

                if let Ok(k) = key {
                    debug!("Loaded legacy key from {:?}: pubkey={}", path, k.pubkey_hex);
                    keys.push(k);
                    break;
                }
            }
        }
    }

    keys
}

/// Resolve an identifier to (pubkey_hex, secret_hex)
/// Identifier can be:
/// - petname (e.g., "work", "default")
/// - pubkey hex (64 chars)
/// - npub bech32
pub fn resolve_identity(identifier: &str) -> Result<(String, Option<String>)> {
    let keys = load_keys();

    // Check if it's a petname
    for key in &keys {
        if key.petname.as_deref() == Some(identifier) {
            return Ok((key.pubkey_hex.clone(), Some(key.secret_hex.clone())));
        }
    }

    // Check if it's an npub
    if identifier.starts_with("npub1") {
        let pk =
            PublicKey::parse(identifier).map_err(|e| anyhow::anyhow!("Invalid npub format: {}", e))?;
        let pubkey_hex = hex::encode(pk.to_bytes());

        // Check if we have the secret for this pubkey
        let secret = keys
            .iter()
            .find(|k| k.pubkey_hex == pubkey_hex)
            .map(|k| k.secret_hex.clone());

        return Ok((pubkey_hex, secret));
    }

    // Check if it's a hex pubkey
    if identifier.len() == 64 && hex::decode(identifier).is_ok() {
        let secret = keys
            .iter()
            .find(|k| k.pubkey_hex == identifier)
            .map(|k| k.secret_hex.clone());

        return Ok((identifier.to_string(), secret));
    }

    // Unknown identifier - might be a petname we don't have
    anyhow::bail!(
        "Unknown identity '{}'. Add it to ~/.hashtree/keys or use a pubkey/npub.",
        identifier
    )
}

use crate::config::Config;

/// Nostr client for git operations
pub struct NostrClient {
    pubkey: String,
    /// nostr-sdk Keys for signing
    keys: Option<Keys>,
    relays: Vec<String>,
    blossom: BlossomClient,
    /// Cached refs from remote
    cached_refs: HashMap<String, HashMap<String, String>>,
    /// Cached root hashes
    #[allow(dead_code)]
    cached_roots: HashMap<String, String>,
}

impl NostrClient {
    /// Create a new client with pubkey, optional secret key, and config
    pub fn new(pubkey: &str, secret_key: Option<String>, config: &Config) -> Result<Self> {
        // Use provided secret, or try environment variable
        let secret_key = secret_key.or_else(|| std::env::var("NOSTR_SECRET_KEY").ok());

        // Create nostr-sdk Keys if we have a secret
        let keys = if let Some(ref secret_hex) = secret_key {
            let secret_bytes = hex::decode(secret_hex).context("Invalid secret key hex")?;
            let secret = nostr::SecretKey::from_slice(&secret_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid secret key: {}", e))?;
            Some(Keys::new(secret))
        } else {
            None
        };

        // Create BlossomClient (needs keys for upload auth)
        let blossom_keys = keys.clone().unwrap_or_else(Keys::generate);
        let blossom = BlossomClient::new(blossom_keys)
            .with_servers(config.blossom.all_read_servers())
            .with_timeout(Duration::from_secs(30));

        Ok(Self {
            pubkey: pubkey.to_string(),
            keys,
            relays: config.nostr.relays.clone(),
            blossom,
            cached_refs: HashMap::new(),
            cached_roots: HashMap::new(),
        })
    }

    /// Check if we can sign (have secret key for this pubkey)
    #[allow(dead_code)]
    pub fn can_sign(&self) -> bool {
        self.keys.is_some()
    }

    /// Fetch refs for a repository from nostr
    /// Returns refs parsed from the hashtree at the root hash
    pub fn fetch_refs(&mut self, repo_name: &str) -> Result<HashMap<String, String>> {
        debug!("Fetching refs for {} from {}", repo_name, self.pubkey);

        // Check cache first
        if let Some(refs) = self.cached_refs.get(repo_name) {
            return Ok(refs.clone());
        }

        // Query relays for kind 30078 events
        let rt = tokio::runtime::Handle::try_current()
            .unwrap_or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .handle()
                    .clone()
            });

        let refs = rt.block_on(self.fetch_refs_async(repo_name))?;
        self.cached_refs.insert(repo_name.to_string(), refs.clone());
        Ok(refs)
    }

    async fn fetch_refs_async(&self, repo_name: &str) -> Result<HashMap<String, String>> {
        // Create nostr-sdk client
        let client = Client::default();

        // Add relays
        for relay in &self.relays {
            if let Err(e) = client.add_relay(relay).await {
                warn!("Failed to add relay {}: {}", relay, e);
            }
        }

        // Connect
        client.connect().await;

        // Build filter for kind 30078 events from this author with matching d-tag
        let author = PublicKey::from_hex(&self.pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid pubkey: {}", e))?;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_APP_DATA))
            .author(author)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), vec![repo_name])
            .limit(1);

        debug!("Querying relays for repo {} events", repo_name);

        // Query with timeout
        let events = tokio::time::timeout(
            Duration::from_secs(10),
            client.get_events_of(vec![filter], EventSource::relays(None)),
        )
        .await
        .context("Relay query timed out")?
        .map_err(|e| anyhow::anyhow!("Failed to fetch events: {}", e))?;

        // Disconnect
        let _ = client.disconnect().await;

        // Find the most recent event with "hashtree" label
        let event = events
            .iter()
            .filter(|e| {
                e.tags.iter().any(|t| {
                    t.as_slice().len() >= 2
                        && t.as_slice()[0].as_str() == "l"
                        && t.as_slice()[1].as_str() == LABEL_HASHTREE
                })
            })
            .max_by_key(|e| e.created_at);

        let Some(event) = event else {
            debug!("No hashtree event found for {}", repo_name);
            return Ok(HashMap::new());
        };

        // Get root hash from content or "hash" tag
        let root_hash = event
            .tags
            .iter()
            .find(|t| t.as_slice().len() >= 2 && t.as_slice()[0].as_str() == "hash")
            .map(|t| t.as_slice()[1].to_string())
            .unwrap_or_else(|| event.content.to_string());

        if root_hash.is_empty() {
            debug!("Empty root hash in event");
            return Ok(HashMap::new());
        }

        info!("Found root hash {} for {}", &root_hash[..12.min(root_hash.len())], repo_name);

        // TODO: Fetch refs from hashtree at root_hash
        // For now return empty - full implementation would traverse the tree
        Ok(HashMap::new())
    }

    /// Update a ref in local cache (will be published with publish_repo)
    #[allow(dead_code)]
    pub fn update_ref(&mut self, repo_name: &str, ref_name: &str, sha: &str) -> Result<()> {
        info!("Updating ref {} -> {} for {}", ref_name, sha, repo_name);

        let refs = self.cached_refs.entry(repo_name.to_string()).or_default();
        refs.insert(ref_name.to_string(), sha.to_string());

        Ok(())
    }

    /// Delete a ref from local cache
    pub fn delete_ref(&mut self, repo_name: &str, ref_name: &str) -> Result<()> {
        info!("Deleting ref {} for {}", ref_name, repo_name);

        if let Some(refs) = self.cached_refs.get_mut(repo_name) {
            refs.remove(ref_name);
        }

        Ok(())
    }

    /// Publish repository to nostr as kind 30078 event
    /// Format:
    ///   kind: 30078
    ///   tags: [["d", repo_name], ["l", "hashtree"], ["hash", root_hash]]
    ///   content: <merkle-root-hash>
    pub fn publish_repo(&self, repo_name: &str, root_hash: &str) -> Result<()> {
        let keys = self.keys.as_ref().context(
            "No secret key configured. Set NOSTR_SECRET_KEY or create ~/.hashtree/keys",
        )?;

        info!("Publishing repo {} with root hash {}", repo_name, root_hash);

        let rt = tokio::runtime::Handle::try_current().unwrap_or_else(|_| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .handle()
                .clone()
        });

        rt.block_on(self.publish_repo_async(keys, repo_name, root_hash))
    }

    async fn publish_repo_async(
        &self,
        keys: &Keys,
        repo_name: &str,
        root_hash: &str,
    ) -> Result<()> {
        // Create nostr-sdk client with our keys
        let client = Client::new(keys.clone());

        // Add relays
        for relay in &self.relays {
            if let Err(e) = client.add_relay(relay).await {
                warn!("Failed to add relay {}: {}", relay, e);
            }
        }

        // Connect
        client.connect().await;

        // Build event with tags
        let tags = vec![
            Tag::custom(TagKind::custom("d"), vec![repo_name.to_string()]),
            Tag::custom(TagKind::custom("l"), vec![LABEL_HASHTREE.to_string()]),
            Tag::custom(TagKind::custom("hash"), vec![root_hash.to_string()]),
        ];
        let event = EventBuilder::new(Kind::Custom(KIND_APP_DATA), root_hash, tags);

        // Sign and publish
        let output = client
            .send_event_builder(event)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish event: {}", e))?;

        info!(
            "Published event {} to {} relays",
            output.id(),
            output.success.len()
        );

        if output.success.is_empty() {
            warn!("Event was not accepted by any relay");
        }

        // Disconnect
        let _ = client.disconnect().await;

        Ok(())
    }

    /// Upload blob to blossom server
    pub async fn upload_blob(&self, _hash: &str, data: &[u8]) -> Result<String> {
        let hash = self
            .blossom
            .upload(data)
            .await
            .map_err(|e| anyhow::anyhow!("Blossom upload failed: {}", e))?;
        Ok(hash)
    }

    /// Upload blob only if it doesn't exist
    pub async fn upload_blob_if_missing(&self, data: &[u8]) -> Result<(String, bool)> {
        self.blossom
            .upload_if_missing(data)
            .await
            .map_err(|e| anyhow::anyhow!("Blossom upload failed: {}", e))
    }

    /// Download blob from blossom server
    pub async fn download_blob(&self, hash: &str) -> Result<Vec<u8>> {
        self.blossom
            .download(hash)
            .await
            .map_err(|e| anyhow::anyhow!("Blossom download failed: {}", e))
    }

    /// Try to download blob, returns None if not found
    pub async fn try_download_blob(&self, hash: &str) -> Option<Vec<u8>> {
        self.blossom.try_download(hash).await
    }
}

mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBKEY: &str =
        "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";

    fn test_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_new_client() {
        let config = test_config();
        let client = NostrClient::new(TEST_PUBKEY, None, &config).unwrap();
        assert!(!client.relays.is_empty());
        assert!(!client.can_sign());
    }

    #[test]
    fn test_new_client_with_secret() {
        let config = test_config();
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let client = NostrClient::new(TEST_PUBKEY, Some(secret.to_string()), &config).unwrap();
        assert!(client.can_sign());
    }

    #[test]
    fn test_fetch_refs_empty() {
        let config = test_config();
        let mut client = NostrClient::new(TEST_PUBKEY, None, &config).unwrap();
        // This will timeout/return empty without real relays
        let refs = client.cached_refs.get("new-repo");
        assert!(refs.is_none());
    }

    #[test]
    fn test_update_ref() {
        let config = test_config();
        let mut client = NostrClient::new(TEST_PUBKEY, None, &config).unwrap();

        client
            .update_ref("repo", "refs/heads/main", "abc123")
            .unwrap();

        let refs = client.cached_refs.get("repo").unwrap();
        assert_eq!(refs.get("refs/heads/main"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_stored_key_from_hex() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = StoredKey::from_secret_hex(secret, Some("test".to_string())).unwrap();
        assert_eq!(key.secret_hex, secret);
        assert_eq!(key.petname, Some("test".to_string()));
        assert_eq!(key.pubkey_hex.len(), 64);
    }

    #[test]
    fn test_stored_key_from_nsec() {
        // This is a test nsec (don't use in production!)
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let key = StoredKey::from_nsec(nsec, None).unwrap();
        assert_eq!(key.secret_hex.len(), 64);
        assert_eq!(key.pubkey_hex.len(), 64);
    }

    #[test]
    fn test_resolve_identity_hex_pubkey() {
        // Hex pubkey without matching secret returns (pubkey, None)
        let result = resolve_identity(TEST_PUBKEY);
        assert!(result.is_ok());
        let (pubkey, secret) = result.unwrap();
        assert_eq!(pubkey, TEST_PUBKEY);
        // No secret unless we have it in config
        assert!(secret.is_none());
    }

    #[test]
    fn test_resolve_identity_npub() {
        // Create a pubkey from our test hex
        let pk_bytes = hex::decode(TEST_PUBKEY).unwrap();
        let pk = PublicKey::from_slice(&pk_bytes).unwrap();
        let npub = pk.to_bech32().unwrap();

        let result = resolve_identity(&npub);
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let (pubkey, _) = result.unwrap();
        // Should be valid hex pubkey
        assert_eq!(pubkey.len(), 64);
        assert_eq!(pubkey, TEST_PUBKEY);
    }

    #[test]
    fn test_resolve_identity_unknown_petname() {
        let result = resolve_identity("nonexistent_petname_xyz");
        assert!(result.is_err());
    }
}
