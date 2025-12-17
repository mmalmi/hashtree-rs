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
use nostr::nips::nip19::FromBech32;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info};

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

        let sk_bytes = hex::decode(secret_hex)
            .context("Invalid hex in secret key")?;
        let sk = SecretKey::from_slice(&sk_bytes)
            .context("Invalid secret key")?;
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
        let secret_key = nostr::SecretKey::from_bech32(nsec)
            .context("Invalid nsec format")?;
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
                debug!("Loaded key: pubkey={}, petname={:?}", k.pubkey_hex, k.petname);
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
        let pk = nostr::PublicKey::from_bech32(identifier)
            .context("Invalid npub format")?;
        let pubkey_hex = hex::encode(pk.to_bytes());

        // Check if we have the secret for this pubkey
        let secret = keys.iter()
            .find(|k| k.pubkey_hex == pubkey_hex)
            .map(|k| k.secret_hex.clone());

        return Ok((pubkey_hex, secret));
    }

    // Check if it's a hex pubkey
    if identifier.len() == 64 && hex::decode(identifier).is_ok() {
        let secret = keys.iter()
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

/// Default blossom servers for blob storage
pub const DEFAULT_BLOSSOM_SERVERS: &[&str] =
    &["https://blossom.primal.net", "https://nostr.download"];

/// Default nostr relays
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://temp.iris.to",
];

/// Nostr client for git operations
pub struct NostrClient {
    pubkey: String,
    /// Private key for signing (hex)
    secret_key: Option<String>,
    relays: Vec<String>,
    blossom_servers: Vec<String>,
    /// Cached refs from remote
    cached_refs: HashMap<String, HashMap<String, String>>,
    /// Cached root hashes
    #[allow(dead_code)]
    cached_roots: HashMap<String, String>,
}

impl NostrClient {
    /// Create a new client with pubkey and optional secret key
    pub fn new(pubkey: &str, secret_key: Option<String>) -> Result<Self> {
        // Use provided secret, or try environment variable
        let secret_key = secret_key.or_else(|| std::env::var("NOSTR_SECRET_KEY").ok());

        Ok(Self {
            pubkey: pubkey.to_string(),
            secret_key,
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            blossom_servers: DEFAULT_BLOSSOM_SERVERS.iter().map(|s| s.to_string()).collect(),
            cached_refs: HashMap::new(),
            cached_roots: HashMap::new(),
        })
    }

    /// Check if we can sign (have secret key for this pubkey)
    #[allow(dead_code)]
    pub fn can_sign(&self) -> bool {
        self.secret_key.is_some()
    }

    /// Fetch refs for a repository from nostr
    /// Returns refs parsed from the hashtree at the root hash
    pub fn fetch_refs(&mut self, repo_name: &str) -> Result<HashMap<String, String>> {
        debug!("Fetching refs for {} from {}", repo_name, self.pubkey);

        // Check cache first
        if let Some(refs) = self.cached_refs.get(repo_name) {
            return Ok(refs.clone());
        }

        // TODO: Query relays for kind 30078 events with:
        //   authors: [self.pubkey]
        //   #d: [repo_name]
        //   #l: ["hashtree"]
        // Then fetch the root hash from content and traverse the tree

        // For now, return empty (new repo)
        let refs = HashMap::new();
        self.cached_refs.insert(repo_name.to_string(), refs.clone());
        Ok(refs)
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
    ///   tags: [["d", repo_name], ["l", "hashtree"]]
    ///   content: <merkle-root-hash>
    pub fn publish_repo(&self, repo_name: &str, root_hash: &str) -> Result<()> {
        let _secret_key = self
            .secret_key
            .as_ref()
            .context("No secret key configured. Set NOSTR_SECRET_KEY or create ~/.config/nostr/secret")?;

        info!(
            "Publishing repo {} with root hash {}",
            repo_name, root_hash
        );

        // Build event tags
        // The hash is in both content (legacy) and 'hash' tag (expected by browser NostrRefResolver)
        let tags = vec![
            vec!["d".to_string(), repo_name.to_string()],
            vec!["l".to_string(), LABEL_HASHTREE.to_string()],
            vec!["hash".to_string(), root_hash.to_string()],
        ];

        eprintln!("[git-remote-htree] Publishing event with tags: {:?}", tags);

        // Create and sign event
        let event = self.create_event(KIND_APP_DATA, &tags, root_hash)?;
        eprintln!("[git-remote-htree] Created event id: {}", event.id);

        // Publish to relays
        self.publish_event(&event)?;

        info!("Published repo event to {} relays", self.relays.len());
        Ok(())
    }

    /// Fetch objects for a repository starting from root hash
    pub fn fetch_objects(&self, _repo_name: &str, _sha: &str) -> Result<Vec<(String, Vec<u8>)>> {
        // TODO: Fetch from blossom servers using hashtree traversal
        Ok(vec![])
    }

    /// Create a nostr event (unsigned)
    fn create_event(
        &self,
        kind: u16,
        tags: &[Vec<String>],
        content: &str,
    ) -> Result<NostrEvent> {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        Ok(NostrEvent {
            id: String::new(),
            pubkey: self.pubkey.clone(),
            created_at,
            kind,
            tags: tags.to_vec(),
            content: content.to_string(),
            sig: String::new(),
        })
    }

    /// Sign and compute event ID
    fn sign_event(&self, event: &mut NostrEvent) -> Result<()> {
        let secret_key = self.secret_key.as_ref().context("No secret key")?;

        // Compute event ID (sha256 of serialized event)
        let serialized = format!(
            "[0,\"{}\",{},{},{},\"{}\"]",
            event.pubkey,
            event.created_at,
            event.kind,
            serde_json::to_string(&event.tags)?,
            event.content
        );

        let id_bytes = Sha256::digest(serialized.as_bytes());
        event.id = hex::encode(id_bytes);

        // Sign with secret key using secp256k1 schnorr signature
        use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_bytes = hex::decode(secret_key)?;
        let sk = SecretKey::from_slice(&sk_bytes)?;
        let message = Message::from_digest_slice(&id_bytes)?;

        let keypair = Keypair::from_secret_key(&secp, &sk);
        let sig = secp.sign_schnorr(&message, &keypair);
        event.sig = hex::encode(sig.as_ref());

        Ok(())
    }

    /// Publish event to relays
    fn publish_event(&self, event: &NostrEvent) -> Result<()> {
        let mut signed_event = event.clone();
        self.sign_event(&mut signed_event)?;

        let event_json = serde_json::to_string(&signed_event)?;
        let _message = format!("[\"EVENT\",{}]", event_json);

        // For each relay, send the event
        for relay in &self.relays {
            debug!("Publishing to {}", relay);
            // TODO: Actually connect and publish via WebSocket
        }

        Ok(())
    }

    /// Upload blob to blossom server
    #[allow(dead_code)]
    pub fn upload_blob(&self, hash: &str, data: &[u8]) -> Result<String> {
        for server in &self.blossom_servers {
            let url = format!("{}/upload", server);
            debug!("Uploading {} bytes to {}", data.len(), url);
            // TODO: Actually upload with reqwest
            return Ok(format!("{}/{}", server, hash));
        }

        anyhow::bail!("Failed to upload to any blossom server")
    }

    /// Download blob from blossom server
    #[allow(dead_code)]
    pub fn download_blob(&self, hash: &str) -> Result<Vec<u8>> {
        for server in &self.blossom_servers {
            let url = format!("{}/{}", server, hash);
            debug!("Downloading from {}", url);
            // TODO: Actually download with reqwest
        }

        anyhow::bail!("Failed to download from any blossom server")
    }
}

/// Simple nostr event structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NostrEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
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

    const TEST_PUBKEY: &str = "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";

    #[test]
    fn test_new_client() {
        let client = NostrClient::new(TEST_PUBKEY, None).unwrap();
        assert_eq!(client.relays.len(), 3);
        assert_eq!(client.blossom_servers.len(), 2);
        assert!(!client.can_sign());
    }

    #[test]
    fn test_new_client_with_secret() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let client = NostrClient::new(TEST_PUBKEY, Some(secret.to_string())).unwrap();
        assert!(client.can_sign());
    }

    #[test]
    fn test_fetch_refs_empty() {
        let mut client = NostrClient::new(TEST_PUBKEY, None).unwrap();
        let refs = client.fetch_refs("new-repo").unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_update_ref() {
        let mut client = NostrClient::new(TEST_PUBKEY, None).unwrap();

        client
            .update_ref("repo", "refs/heads/main", "abc123")
            .unwrap();

        let refs = client.fetch_refs("repo").unwrap();
        assert_eq!(refs.get("refs/heads/main"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_event_format() {
        let client = NostrClient::new(TEST_PUBKEY, None).unwrap();

        let tags = vec![
            vec!["d".to_string(), "myrepo".to_string()],
            vec!["l".to_string(), "hashtree".to_string()],
            vec!["hash".to_string(), "abc123root".to_string()],
        ];

        let event = client
            .create_event(KIND_APP_DATA, &tags, "abc123root")
            .unwrap();

        assert_eq!(event.kind, 30078);
        assert_eq!(event.content, "abc123root");
        assert_eq!(event.tags[0], vec!["d", "myrepo"]);
        assert_eq!(event.tags[1], vec!["l", "hashtree"]);
        assert_eq!(event.tags[2], vec!["hash", "abc123root"]);
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
        // Use a valid npub - generate one properly from the nostr crate
        use nostr::nips::nip19::ToBech32;

        // Create a pubkey from our test hex
        let pk_bytes = hex::decode(TEST_PUBKEY).unwrap();
        let pk = nostr::PublicKey::from_slice(&pk_bytes).unwrap();
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
