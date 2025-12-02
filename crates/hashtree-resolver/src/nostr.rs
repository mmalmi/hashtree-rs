//! Nostr-based root resolver
//!
//! Maps npub/treename keys to merkle root hashes using Nostr events.
//!
//! Key format: "npub1.../treename"
//!
//! Uses kind 30078 (APP_DATA) events with:
//! - d-tag: tree name (NIP-33 replaceable)
//! - l-tag: "hashtree" (for filtering)
//! - content: hex-encoded hash

use crate::{ResolverEntry, ResolverError, RootResolver};
use async_trait::async_trait;
use hashtree::{from_hex, to_hex, Hash};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

const HASHTREE_KIND: u16 = 30078;
const HASHTREE_LABEL: &str = "hashtree";

/// Configuration for NostrRootResolver
#[derive(Clone)]
pub struct NostrResolverConfig {
    /// Nostr relays to connect to
    pub relays: Vec<String>,
    /// Timeout for one-shot resolve operations
    pub resolve_timeout: Duration,
    /// Secret key for publishing (optional)
    pub secret_key: Option<Keys>,
}

impl Default for NostrResolverConfig {
    fn default() -> Self {
        Self {
            relays: vec![
                "wss://relay.damus.io".into(),
                "wss://relay.primal.net".into(),
                "wss://nos.lol".into(),
            ],
            resolve_timeout: Duration::from_millis(500),
            secret_key: None,
        }
    }
}

/// Subscription state
struct Subscription {
    tx: mpsc::Sender<Option<Hash>>,
    current_hash: Option<String>,
    latest_created_at: Timestamp,
}

/// NostrRootResolver - Maps npub/treename keys to merkle root hashes
pub struct NostrRootResolver {
    client: Client,
    config: NostrResolverConfig,
    subscriptions: Arc<RwLock<HashMap<String, Subscription>>>,
}

impl NostrRootResolver {
    /// Create a new NostrRootResolver
    pub async fn new(config: NostrResolverConfig) -> Result<Self, ResolverError> {
        let keys = config.secret_key.clone().unwrap_or_else(Keys::generate);
        let client = Client::new(keys);

        // Add relays
        for relay in &config.relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| ResolverError::Network(e.to_string()))?;
        }

        // Connect
        client.connect().await;

        Ok(Self {
            client,
            config,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Parse a key into pubkey and tree name
    fn parse_key(key: &str) -> Result<(PublicKey, String), ResolverError> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 2 {
            return Err(ResolverError::InvalidKey(format!(
                "Key must be in format 'npub.../treename', got: {}",
                key
            )));
        }

        let npub_str = parts[0];
        let tree_name = parts[1].to_string();

        let pubkey = PublicKey::from_bech32(npub_str)
            .map_err(|_| ResolverError::InvalidKey(format!("Invalid npub: {}", npub_str)))?;

        Ok((pubkey, tree_name))
    }

    /// Get current user's public key (if we have a secret key)
    pub fn pubkey(&self) -> Option<PublicKey> {
        self.config.secret_key.as_ref().map(|k| k.public_key())
    }

    /// Resolve a key, waiting indefinitely until found.
    ///
    /// Unlike `resolve()` which returns `None` after timeout, this method
    /// subscribes and waits until a hash is found. Caller should apply their
    /// own timeout if needed (e.g., via `tokio::time::timeout`).
    ///
    /// This matches the behavior of hashtree-ts NostrRootResolver.
    pub async fn resolve_wait(&self, key: &str) -> Result<Hash, ResolverError> {
        // First try a quick resolve
        if let Some(hash) = self.resolve(key).await? {
            return Ok(hash);
        }

        // Not found, subscribe and wait
        let mut rx = self.subscribe(key).await?;

        // Wait for first non-None value
        while let Some(maybe_hash) = rx.recv().await {
            if let Some(hash) = maybe_hash {
                return Ok(hash);
            }
        }

        Err(ResolverError::Stopped)
    }
}

#[async_trait]
impl RootResolver for NostrRootResolver {
    async fn resolve(&self, key: &str) -> Result<Option<Hash>, ResolverError> {
        let (pubkey, tree_name) = Self::parse_key(key)?;

        // Create filter for this specific tree
        let filter = Filter::new()
            .kind(Kind::Custom(HASHTREE_KIND))
            .author(pubkey)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), vec![tree_name.clone()])
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), vec![HASHTREE_LABEL]);

        // Fetch events from relays
        let source = EventSource::relays(Some(self.config.resolve_timeout));
        let events = self
            .client
            .get_events_of(vec![filter], source)
            .await
            .map_err(|e| ResolverError::Network(e.to_string()))?;

        // Find the latest event with matching d-tag
        let mut latest_hash: Option<String> = None;
        let mut latest_created_at = Timestamp::from(0);

        for event in events.iter() {
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

            if event.created_at > latest_created_at {
                latest_created_at = event.created_at;
                latest_hash = Some(event.content.clone());
            }
        }

        // Convert hex to hash
        match latest_hash {
            Some(hex) => {
                let hash = from_hex(&hex)
                    .map_err(|_| ResolverError::Other(format!("Invalid hash hex: {}", hex)))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    async fn subscribe(&self, key: &str) -> Result<mpsc::Receiver<Option<Hash>>, ResolverError> {
        let (pubkey, tree_name) = Self::parse_key(key)?;

        let (tx, rx) = mpsc::channel(16);

        // Check if we already have a subscription
        {
            let subs = self.subscriptions.read().await;
            if let Some(sub) = subs.get(key) {
                // Send current value
                let hash = sub
                    .current_hash
                    .as_ref()
                    .and_then(|h| from_hex(h).ok());
                let _ = tx.send(hash).await;
                // Note: In production, you'd want to share subscriptions
                // For simplicity, we create a new one
            }
        }

        // Create filter
        let filter = Filter::new()
            .kind(Kind::Custom(HASHTREE_KIND))
            .author(pubkey)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), vec![tree_name.clone()])
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), vec![HASHTREE_LABEL]);

        // Store subscription state
        {
            let mut subs = self.subscriptions.write().await;
            subs.insert(
                key.to_string(),
                Subscription {
                    tx: tx.clone(),
                    current_hash: None,
                    latest_created_at: Timestamp::from(0),
                },
            );
        }

        // Subscribe to events
        let subscriptions = self.subscriptions.clone();
        let key_clone = key.to_string();
        let tree_name_clone = tree_name.clone();

        // Spawn subscription handler
        let client = self.client.clone();
        tokio::spawn(async move {
            let sub_id = client
                .subscribe(vec![filter], None)
                .await;

            if sub_id.is_err() {
                return;
            }

            // Handle incoming events via notifications
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

                    if d_tag.as_deref() != Some(&tree_name_clone) {
                        continue;
                    }

                    let mut subs = subscriptions.write().await;
                    if let Some(sub) = subs.get_mut(&key_clone) {
                        if event.created_at >= sub.latest_created_at
                            && Some(event.content.clone()) != sub.current_hash
                        {
                            sub.current_hash = Some(event.content.clone());
                            sub.latest_created_at = event.created_at;

                            let hash = from_hex(&event.content).ok();
                            if sub.tx.send(hash).await.is_err() {
                                // Receiver dropped, clean up
                                subs.remove(&key_clone);
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    async fn publish(&self, key: &str, hash: Hash) -> Result<bool, ResolverError> {
        let (pubkey, tree_name) = Self::parse_key(key)?;

        // Check we own this key
        let my_pubkey = self.pubkey().ok_or(ResolverError::NotAuthorized)?;
        if pubkey != my_pubkey {
            return Err(ResolverError::NotAuthorized);
        }

        let hash_hex = to_hex(&hash);

        // Build event with tags
        let tags = vec![
            Tag::identifier(tree_name.clone()),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                vec![HASHTREE_LABEL],
            ),
        ];
        let event = EventBuilder::new(Kind::Custom(HASHTREE_KIND), hash_hex, tags);

        // Publish
        let output = self
            .client
            .send_event_builder(event)
            .await
            .map_err(|e| ResolverError::Network(e.to_string()))?;

        // Update local subscription state
        {
            let mut subs = self.subscriptions.write().await;
            if let Some(sub) = subs.get_mut(key) {
                sub.current_hash = Some(to_hex(&hash));
                sub.latest_created_at = Timestamp::now();
                let _ = sub.tx.send(Some(hash)).await;
            }
        }

        Ok(!output.failed.is_empty() || !output.success.is_empty())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ResolverEntry>, ResolverError> {
        let parts: Vec<&str> = prefix.split('/').collect();
        if parts.is_empty() {
            return Ok(vec![]);
        }

        let npub_str = parts[0];
        let pubkey = PublicKey::from_bech32(npub_str)
            .map_err(|_| ResolverError::InvalidKey(format!("Invalid npub: {}", npub_str)))?;

        // Filter for all hashtree events from this author
        let filter = Filter::new()
            .kind(Kind::Custom(HASHTREE_KIND))
            .author(pubkey)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), vec![HASHTREE_LABEL]);

        let source = EventSource::relays(Some(self.config.resolve_timeout));
        let events = self
            .client
            .get_events_of(vec![filter], source)
            .await
            .map_err(|e| ResolverError::Network(e.to_string()))?;

        // Deduplicate by d-tag, keeping latest
        let mut entries_by_d_tag: HashMap<String, (String, Timestamp)> = HashMap::new();

        for event in events.iter() {
            let d_tag = event.tags.iter().find_map(|tag| {
                if let Some(TagStandard::Identifier(id)) = tag.as_standardized() {
                    Some(id.clone())
                } else {
                    None
                }
            });

            if let Some(d_tag) = d_tag {
                let existing = entries_by_d_tag.get(&d_tag);
                if existing.is_none() || existing.unwrap().1 < event.created_at {
                    entries_by_d_tag.insert(d_tag, (event.content.clone(), event.created_at));
                }
            }
        }

        // Convert to entries
        let mut result = Vec::new();
        for (d_tag, (hash_hex, _)) in entries_by_d_tag {
            if let Ok(hash) = from_hex(&hash_hex) {
                result.push(ResolverEntry {
                    key: format!("{}/{}", npub_str, d_tag),
                    hash,
                });
            }
        }

        Ok(result)
    }

    async fn stop(&self) -> Result<(), ResolverError> {
        let _ = self.client.disconnect().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_valid() {
        // Generate a valid npub for testing
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();
        let key = format!("{}/mytree", npub);

        let result = NostrRootResolver::parse_key(&key);
        assert!(result.is_ok());
        let (pubkey, tree_name) = result.unwrap();
        assert_eq!(pubkey, keys.public_key());
        assert_eq!(tree_name, "mytree");
    }

    #[test]
    fn test_parse_key_invalid_format() {
        let key = "notvalid";
        let result = NostrRootResolver::parse_key(key);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_key_invalid_npub() {
        let key = "notannpub/mytree";
        let result = NostrRootResolver::parse_key(key);
        assert!(result.is_err());
    }
}
