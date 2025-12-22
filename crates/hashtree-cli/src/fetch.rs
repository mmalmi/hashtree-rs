//! Remote content fetching with WebRTC and Blossom fallback
//!
//! Provides shared logic for fetching content from:
//! 1. Local storage (first)
//! 2. WebRTC peers (second)
//! 3. Blossom HTTP servers (fallback)

use anyhow::Result;
use hashtree_blossom::BlossomClient;
use hashtree_core::{decode_tree_node, to_hex};
use nostr::Keys;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::storage::HashtreeStore;
use crate::webrtc::WebRTCState;

/// Configuration for remote fetching
#[derive(Clone)]
pub struct FetchConfig {
    /// Timeout for WebRTC requests
    pub webrtc_timeout: Duration,
    /// Timeout for Blossom requests
    pub blossom_timeout: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            webrtc_timeout: Duration::from_millis(2000),
            blossom_timeout: Duration::from_millis(10000),
        }
    }
}

/// Fetcher for remote content
pub struct Fetcher {
    config: FetchConfig,
    blossom: BlossomClient,
}

impl Fetcher {
    /// Create a new fetcher with the given config
    /// BlossomClient auto-loads servers from ~/.hashtree/config.toml
    pub fn new(config: FetchConfig) -> Self {
        // Generate ephemeral keys for downloads (no signing needed)
        let keys = Keys::generate();
        let blossom = BlossomClient::new(keys)
            .with_timeout(config.blossom_timeout);

        Self { config, blossom }
    }

    /// Create a new fetcher with specific keys (for authenticated uploads)
    pub fn with_keys(config: FetchConfig, keys: Keys) -> Self {
        let blossom = BlossomClient::new(keys)
            .with_timeout(config.blossom_timeout);

        Self { config, blossom }
    }

    /// Get the underlying BlossomClient
    pub fn blossom(&self) -> &BlossomClient {
        &self.blossom
    }

    /// Fetch a single chunk by hash, trying WebRTC first then Blossom
    pub async fn fetch_chunk(
        &self,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash_hex: &str,
    ) -> Result<Vec<u8>> {
        let short_hash = if hash_hex.len() >= 12 {
            &hash_hex[..12]
        } else {
            hash_hex
        };

        // Try WebRTC first
        if let Some(state) = webrtc_state {
            debug!("Trying WebRTC for {}", short_hash);
            let webrtc_result = tokio::time::timeout(
                self.config.webrtc_timeout,
                state.request_from_peers(hash_hex),
            )
            .await;

            if let Ok(Some(data)) = webrtc_result {
                debug!("Got {} from WebRTC ({} bytes)", short_hash, data.len());
                return Ok(data);
            }
        }

        // Fallback to Blossom
        debug!("Trying Blossom for {}", short_hash);
        match self.blossom.download(hash_hex).await {
            Ok(data) => {
                debug!("Got {} from Blossom ({} bytes)", short_hash, data.len());
                Ok(data)
            }
            Err(e) => {
                debug!("Blossom download failed for {}: {}", short_hash, e);
                Err(anyhow::anyhow!("Failed to fetch {} from any source: {}", short_hash, e))
            }
        }
    }

    /// Fetch a chunk, checking local storage first
    pub async fn fetch_chunk_with_store(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        // Check local storage first
        if let Some(data) = store.get_chunk(hash)? {
            return Ok(data);
        }

        // Fetch remotely and store
        let hash_hex = to_hex(hash);
        let data = self.fetch_chunk(webrtc_state, &hash_hex).await?;
        store.put_blob(&data)?;
        Ok(data)
    }

    /// Fetch an entire tree (all chunks recursively)
    /// Returns (chunks_fetched, bytes_fetched)
    pub async fn fetch_tree(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        root_hash: &[u8; 32],
    ) -> Result<(usize, u64)> {
        let mut chunks_fetched = 0usize;
        let mut bytes_fetched = 0u64;

        // Check if we already have the root
        if store.blob_exists(root_hash)? {
            return Ok((0, 0));
        }

        // BFS to fetch all chunks
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        queue.push_back(*root_hash);

        while let Some(hash) = queue.pop_front() {
            // Check if we already have it
            if store.blob_exists(&hash)? {
                continue;
            }

            let hash_hex = to_hex(&hash);

            // Fetch it
            let data = self.fetch_chunk(webrtc_state, &hash_hex).await?;

            // Store it
            store.put_blob(&data)?;
            chunks_fetched += 1;
            bytes_fetched += data.len() as u64;

            // Parse as tree node and queue children
            if let Ok(node) = decode_tree_node(&data) {
                for link in node.links {
                    queue.push_back(link.hash);
                }
            }
        }

        Ok((chunks_fetched, bytes_fetched))
    }

    /// Fetch a file by hash, fetching all chunks if needed
    /// Returns the complete file content
    pub async fn fetch_file(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        // First, try to get from local storage
        if let Some(content) = store.get_file(hash)? {
            return Ok(Some(content));
        }

        // Fetch the tree
        self.fetch_tree(store, webrtc_state, hash).await?;

        // Now try to read the file
        store.get_file(hash)
    }

    /// Fetch a directory listing, fetching chunks if needed
    pub async fn fetch_directory(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash: &[u8; 32],
    ) -> Result<Option<crate::storage::DirectoryListing>> {
        // First, try to get from local storage
        if let Ok(Some(listing)) = store.get_directory_listing(hash) {
            return Ok(Some(listing));
        }

        // Fetch the tree
        self.fetch_tree(store, webrtc_state, hash).await?;

        // Now try to get the directory listing
        store.get_directory_listing(hash)
    }

    /// Upload data to Blossom servers
    pub async fn upload(&self, data: &[u8]) -> Result<String> {
        self.blossom
            .upload(data)
            .await
            .map_err(|e| anyhow::anyhow!("Blossom upload failed: {}", e))
    }

    /// Upload data if it doesn't already exist
    pub async fn upload_if_missing(&self, data: &[u8]) -> Result<(String, bool)> {
        self.blossom
            .upload_if_missing(data)
            .await
            .map_err(|e| anyhow::anyhow!("Blossom upload failed: {}", e))
    }
}
