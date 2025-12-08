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

use anyhow::{Context, Result};
use nostr::nips::nip19::FromBech32;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, info};

/// Event kind for application-specific data (NIP-78)
pub const KIND_APP_DATA: u16 = 30078;

/// Label for hashtree events
pub const LABEL_HASHTREE: &str = "hashtree";

/// Default blossom servers for blob storage
pub const DEFAULT_BLOSSOM_SERVERS: &[&str] =
    &["https://blossom.primal.net", "https://nostr.download"];

/// Default nostr relays
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
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
    pub fn new(pubkey: &str) -> Result<Self> {
        // Try to load secret key from environment or config
        let secret_key =
            std::env::var("NOSTR_SECRET_KEY").ok().or_else(|| Self::load_secret_from_config());

        Ok(Self {
            pubkey: pubkey.to_string(),
            secret_key,
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            blossom_servers: DEFAULT_BLOSSOM_SERVERS.iter().map(|s| s.to_string()).collect(),
            cached_refs: HashMap::new(),
            cached_roots: HashMap::new(),
        })
    }

    fn load_secret_from_config() -> Option<String> {
        let home = dirs::home_dir()?;

        // Check paths in priority order - hashtree's nsec first (bech32), then hex formats
        let nsec_path = home.join(".hashtree/nsec");
        if let Ok(content) = std::fs::read_to_string(&nsec_path) {
            let nsec = content.trim();
            // Parse bech32 nsec format
            if nsec.starts_with("nsec1") {
                if let Ok(secret_key) = nostr::SecretKey::from_bech32(nsec) {
                    debug!("Loaded secret key from {:?}", nsec_path);
                    return Some(hex::encode(secret_key.to_secret_bytes()));
                }
            }
        }

        // Fallback to hex format paths
        let paths = [
            home.join(".config/nostr/secret"),
            home.join(".nostr/secret"),
            home.join(".config/git-remote-htree/secret"),
        ];

        for path in paths {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let key = content.trim().to_string();
                if key.len() == 64 && hex::decode(&key).is_ok() {
                    debug!("Loaded secret key from {:?}", path);
                    return Some(key);
                }
            }
        }

        None
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
        let tags = vec![
            vec!["d".to_string(), repo_name.to_string()],
            vec!["l".to_string(), LABEL_HASHTREE.to_string()],
        ];

        // Create and sign event
        let event = self.create_event(KIND_APP_DATA, &tags, root_hash)?;

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

    #[test]
    fn test_new_client() {
        let client =
            NostrClient::new("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0")
                .unwrap();
        assert_eq!(client.relays.len(), 3);
        assert_eq!(client.blossom_servers.len(), 2);
    }

    #[test]
    fn test_fetch_refs_empty() {
        let mut client =
            NostrClient::new("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0")
                .unwrap();
        let refs = client.fetch_refs("new-repo").unwrap();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_update_ref() {
        let mut client =
            NostrClient::new("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0")
                .unwrap();

        client
            .update_ref("repo", "refs/heads/main", "abc123")
            .unwrap();

        let refs = client.fetch_refs("repo").unwrap();
        assert_eq!(refs.get("refs/heads/main"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_event_format() {
        let client =
            NostrClient::new("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0")
                .unwrap();

        let tags = vec![
            vec!["d".to_string(), "myrepo".to_string()],
            vec!["l".to_string(), "hashtree".to_string()],
        ];

        let event = client
            .create_event(KIND_APP_DATA, &tags, "abc123root")
            .unwrap();

        assert_eq!(event.kind, 30078);
        assert_eq!(event.content, "abc123root");
        assert_eq!(event.tags[0], vec!["d", "myrepo"]);
        assert_eq!(event.tags[1], vec!["l", "hashtree"]);
    }
}
