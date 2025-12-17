//! Remote content fetching with WebRTC and Blossom fallback
//!
//! Provides shared logic for fetching content from:
//! 1. Local storage (first)
//! 2. WebRTC peers (second)
//! 3. Blossom HTTP servers (fallback)

use anyhow::Result;
use hashtree_core::{decode_tree_node, to_hex};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::storage::HashtreeStore;
use crate::webrtc::WebRTCState;

/// Configuration for remote fetching
#[derive(Clone)]
pub struct FetchConfig {
    /// Blossom servers for fallback
    pub blossom_servers: Vec<String>,
    /// Timeout for WebRTC requests
    pub webrtc_timeout: Duration,
    /// Timeout for Blossom requests
    pub blossom_timeout: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            blossom_servers: vec!["https://blossom.iris.to".to_string()],
            webrtc_timeout: Duration::from_millis(2000),
            blossom_timeout: Duration::from_millis(10000),
        }
    }
}

/// Fetcher for remote content
pub struct Fetcher {
    config: FetchConfig,
    http_client: reqwest::Client,
}

impl Fetcher {
    /// Create a new fetcher with the given config
    pub fn new(config: FetchConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
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
        for server in &self.config.blossom_servers {
            let url = format!("{}/{}", server.trim_end_matches('/'), hash_hex);
            debug!("Trying Blossom {} for {}", server, short_hash);

            let result = tokio::time::timeout(
                self.config.blossom_timeout,
                self.http_client.get(&url).send(),
            )
            .await;

            match result {
                Ok(Ok(response)) if response.status().is_success() => {
                    if let Ok(data) = response.bytes().await {
                        debug!("Got {} from Blossom ({} bytes)", short_hash, data.len());
                        return Ok(data.to_vec());
                    }
                }
                Ok(Ok(response)) => {
                    debug!("Blossom {} returned {} for {}", server, response.status(), short_hash);
                }
                Ok(Err(e)) => {
                    debug!("Blossom {} error for {}: {}", server, short_hash, e);
                }
                Err(_) => {
                    debug!("Blossom {} timeout for {}", server, short_hash);
                }
            }
        }

        Err(anyhow::anyhow!("Failed to fetch {} from any source", short_hash))
    }

    /// Fetch a chunk, checking local storage first
    pub async fn fetch_chunk_with_store(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash_hex: &str,
    ) -> Result<Vec<u8>> {
        // Check local storage first
        if let Some(data) = store.get_chunk(hash_hex)? {
            return Ok(data);
        }

        // Fetch remotely and store
        let data = self.fetch_chunk(webrtc_state, hash_hex).await?;
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

        let root_hex = to_hex(root_hash);

        // Check if we already have the root
        if store.blob_exists(&root_hex)? {
            return Ok((0, 0));
        }

        // BFS to fetch all chunks
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        queue.push_back(*root_hash);

        while let Some(hash) = queue.pop_front() {
            let hash_hex = to_hex(&hash);

            // Check if we already have it
            if store.blob_exists(&hash_hex)? {
                continue;
            }

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
        hash_hex: &str,
    ) -> Result<Option<Vec<u8>>> {
        // First, try to get from local storage
        if let Some(content) = store.get_file(hash_hex)? {
            return Ok(Some(content));
        }

        // Parse hash
        let hash = hashtree_core::from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        // Fetch the tree
        self.fetch_tree(store, webrtc_state, &hash).await?;

        // Now try to read the file
        store.get_file(hash_hex)
    }

    /// Fetch a directory listing, fetching chunks if needed
    pub async fn fetch_directory(
        &self,
        store: &HashtreeStore,
        webrtc_state: Option<&Arc<WebRTCState>>,
        hash_hex: &str,
    ) -> Result<Option<crate::storage::DirectoryListing>> {
        // First, try to get from local storage
        if let Ok(Some(listing)) = store.get_directory_listing(hash_hex) {
            return Ok(Some(listing));
        }

        // Parse hash
        let hash = hashtree_core::from_hex(hash_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;

        // Fetch the tree
        self.fetch_tree(store, webrtc_state, &hash).await?;

        // Now try to get the directory listing
        store.get_directory_listing(hash_hex)
    }
}
