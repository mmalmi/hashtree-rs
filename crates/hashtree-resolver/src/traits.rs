//! Core traits for root resolvers

use async_trait::async_trait;
use hashtree::Hash;
use thiserror::Error;
use tokio::sync::mpsc;

/// Errors that can occur during resolution
#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Not authorized to publish")]
    NotAuthorized,

    #[error("Resolver stopped")]
    Stopped,

    #[error("Other error: {0}")]
    Other(String),
}

/// Entry in a resolver list
#[derive(Debug, Clone)]
pub struct ResolverEntry {
    pub key: String,
    pub hash: Hash,
}

/// RootResolver - Maps human-readable keys to merkle root hashes
///
/// This abstraction allows different backends (Nostr, DNS, HTTP, local storage)
/// to provide mutable pointers to immutable content-addressed data.
///
/// Unlike the TypeScript version which uses callbacks, this Rust version uses
/// channels which are more idiomatic for async Rust.
#[async_trait]
pub trait RootResolver: Send + Sync {
    /// Resolve a key to its current root hash (one-shot)
    ///
    /// Returns None if the key doesn't exist or can't be resolved.
    async fn resolve(&self, key: &str) -> Result<Option<Hash>, ResolverError>;

    /// Subscribe to root hash changes for a key.
    ///
    /// Returns a channel receiver that will receive the current value immediately,
    /// then subsequent updates. The channel is closed when the subscription ends.
    ///
    /// To unsubscribe, simply drop the receiver.
    async fn subscribe(&self, key: &str) -> Result<mpsc::Receiver<Option<Hash>>, ResolverError>;

    /// Publish/update a root hash (optional - only for writable backends)
    ///
    /// Returns true if published successfully.
    async fn publish(&self, key: &str, hash: Hash) -> Result<bool, ResolverError> {
        let _ = (key, hash);
        Err(ResolverError::NotAuthorized)
    }

    /// List all keys matching a prefix (one-shot)
    ///
    /// Returns array of matching keys with their current hashes.
    async fn list(&self, prefix: &str) -> Result<Vec<ResolverEntry>, ResolverError> {
        let _ = prefix;
        Ok(vec![])
    }

    /// Subscribe to list changes for a prefix.
    ///
    /// Returns a channel receiver that will receive the current list immediately,
    /// then the full updated list on each add/remove/update.
    async fn subscribe_list(
        &self,
        prefix: &str,
    ) -> Result<mpsc::Receiver<Vec<ResolverEntry>>, ResolverError> {
        let _ = prefix;
        Err(ResolverError::Other("Not implemented".into()))
    }

    /// Stop the resolver and clean up resources
    async fn stop(&self) -> Result<(), ResolverError> {
        Ok(())
    }
}
