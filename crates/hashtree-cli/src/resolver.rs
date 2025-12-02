//! Nostr-based root resolver for hashtree
//!
//! Maps npub/treename keys to hashtree root hashes using Nostr events.
//! Compatible with hashtree-ts NostrRootResolver.
//!
//! Uses kind 30078 (APP_DATA) events with:
//! - d-tag: tree name (NIP-33 replaceable)
//! - l-tag: "hashtree" (for filtering)
//! - content: hex-encoded hash

use anyhow::Result;
use nostr_sdk::prelude::*;
use std::time::Duration;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

const HASHTREE_KIND: u16 = 30078;
const HASHTREE_LABEL: &str = "hashtree";

/// Simple resolver that fetches from relays on-demand
pub struct NostrResolver {
    relays: Vec<String>,
    /// Cache of resolved hashes (key -> (hash_hex, timestamp))
    cache: Arc<RwLock<HashMap<String, (String, u64)>>>,
}

impl NostrResolver {
    pub fn new(relays: Vec<String>) -> Self {
        Self {
            relays,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Parse a key into pubkey and tree name
    /// Key format: "npub1.../treename" or "hex_pubkey/treename"
    fn parse_key(key: &str) -> Result<(PublicKey, String)> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Key must be in format 'npub.../treename' or 'pubkey_hex/treename'");
        }

        let pubkey_str = parts[0];
        let tree_name = parts[1].to_string();

        // Try bech32 (npub) first, then hex
        let pubkey = if pubkey_str.starts_with("npub") {
            PublicKey::from_bech32(pubkey_str)?
        } else {
            PublicKey::from_hex(pubkey_str)?
        };

        Ok((pubkey, tree_name))
    }

    /// Resolve a key to its current root hash.
    /// Waits indefinitely until a hash is found - caller should apply timeout if needed.
    pub async fn resolve(&self, key: &str) -> Result<String> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some((hash, _ts)) = cache.get(key) {
                return Ok(hash.clone());
            }
        }

        let (pubkey, tree_name) = Self::parse_key(key)?;

        // Connect and subscribe
        let client = Client::new(Keys::generate());
        for relay in &self.relays {
            let _ = client.add_relay(relay).await;
        }
        client.connect().await;

        // Create filter
        let filter = Filter::new()
            .kind(Kind::Custom(HASHTREE_KIND))
            .author(pubkey)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), vec![tree_name.clone()])
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), vec![HASHTREE_LABEL]);

        // Subscribe and wait for first matching event
        let _ = client.subscribe(vec![filter], None).await;

        let mut latest_hash: Option<String> = None;
        let mut latest_ts: u64 = 0;

        // Listen for events until we find one
        let mut notifications = client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event { event, .. } = notification {
                // Verify d-tag matches
                let d_tag = event.tags.iter().find_map(|tag| {
                    if let Some(TagStandard::Identifier(id)) = tag.as_standardized() {
                        Some(id.clone())
                    } else {
                        None
                    }
                });

                if d_tag.as_deref() != Some(&tree_name) {
                    continue;
                }

                let ts = event.created_at.as_u64();
                if ts > latest_ts {
                    latest_ts = ts;
                    latest_hash = Some(event.content.clone());
                }

                // Got a hash, we can return
                if latest_hash.is_some() {
                    break;
                }
            }
        }

        let _ = client.disconnect().await;

        // Update cache and return
        if let Some(ref hash) = latest_hash {
            let mut cache = self.cache.write().await;
            cache.insert(key.to_string(), (hash.clone(), latest_ts));
            Ok(hash.clone())
        } else {
            // This shouldn't happen if we broke out of the loop with a hash
            anyhow::bail!("Subscription ended without finding hash")
        }
    }

    /// List all trees for a user (with timeout for snapshot)
    /// For streaming, use subscribe_list instead
    pub async fn list(&self, npub_or_hex: &str, timeout: Duration) -> Result<Vec<(String, String)>> {
        let pubkey = if npub_or_hex.starts_with("npub") {
            PublicKey::from_bech32(npub_or_hex)?
        } else {
            PublicKey::from_hex(npub_or_hex)?
        };

        let client = Client::new(Keys::generate());
        for relay in &self.relays {
            let _ = client.add_relay(relay).await;
        }
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(HASHTREE_KIND))
            .author(pubkey)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), vec![HASHTREE_LABEL]);

        let events = client.get_events_of(vec![filter], EventSource::relays(Some(timeout))).await?;

        let _ = client.disconnect().await;

        // Deduplicate by d-tag, keeping latest
        let mut trees: HashMap<String, (String, u64)> = HashMap::new();

        for event in events.iter() {
            let d_tag = event.tags.iter().find_map(|tag| {
                if let Some(TagStandard::Identifier(id)) = tag.as_standardized() {
                    Some(id.clone())
                } else {
                    None
                }
            });

            if let Some(tree_name) = d_tag {
                let ts = event.created_at.as_u64();
                if !trees.contains_key(&tree_name) || trees[&tree_name].1 < ts {
                    trees.insert(tree_name, (event.content.clone(), ts));
                }
            }
        }

        Ok(trees.into_iter().map(|(name, (hash, _))| (name, hash)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_npub() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let key = format!("{}/mytree", npub);

        let result = NostrResolver::parse_key(&key);
        assert!(result.is_ok());
        let (pubkey, tree_name) = result.unwrap();
        assert_eq!(pubkey, keys.public_key());
        assert_eq!(tree_name, "mytree");
    }

    #[test]
    fn test_parse_key_hex() {
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let key = format!("{}/mytree", hex);

        let result = NostrResolver::parse_key(&key);
        assert!(result.is_ok());
        let (pubkey, tree_name) = result.unwrap();
        assert_eq!(pubkey, keys.public_key());
        assert_eq!(tree_name, "mytree");
    }

    #[test]
    fn test_parse_key_invalid() {
        let result = NostrResolver::parse_key("notvalid");
        assert!(result.is_err());
    }
}
