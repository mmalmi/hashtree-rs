//! WebRTC-backed store implementation
//!
//! Implements the Store trait by fetching data from connected WebRTC peers.
//! Uses Nostr relays for peer discovery and signaling.

use crate::peer::{Peer, PeerError};
use crate::types::{
    PeerId, PeerState, SignalingMessage, WebRTCStats, WebRTCStoreConfig, NOSTR_KIND_HASHTREE,
};
use async_trait::async_trait;
use hashtree_core::{to_hex, Hash, Store, StoreError};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum WebRTCStoreError {
    #[error("Peer error: {0}")]
    Peer(#[from] PeerError),
    #[error("Nostr error: {0}")]
    Nostr(String),
    #[error("No peers available")]
    NoPeers,
    #[error("Data not found")]
    NotFound,
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
}

/// WebRTC store that fetches data from P2P network
pub struct WebRTCStore<S: Store> {
    /// Local backing store
    local_store: Arc<S>,
    /// Configuration
    config: WebRTCStoreConfig,
    /// Nostr client for signaling
    client: Option<Client>,
    /// Local peer identifier
    peer_id: PeerId,
    /// Connected peers
    peers: Arc<RwLock<HashMap<String, Arc<Peer<S>>>>>,
    /// Known peer roots (peer_id -> Vec<root_hash>)
    peer_roots: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Signaling message sender
    signaling_tx: mpsc::Sender<SignalingMessage>,
    /// Signaling message receiver
    signaling_rx: Arc<RwLock<Option<mpsc::Receiver<SignalingMessage>>>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
    /// Statistics
    stats: Arc<RwLock<WebRTCStats>>,
}

impl<S: Store + 'static> WebRTCStore<S> {
    /// Create a new WebRTC store
    pub fn new(local_store: Arc<S>, config: WebRTCStoreConfig) -> Self {
        let (signaling_tx, signaling_rx) = mpsc::channel(100);

        let peer_id = PeerId::new(String::new(), Uuid::new_v4().to_string());

        Self {
            local_store,
            config,
            client: None,
            peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_roots: Arc::new(RwLock::new(HashMap::new())),
            signaling_tx,
            signaling_rx: Arc::new(RwLock::new(Some(signaling_rx))),
            running: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(WebRTCStats::default())),
        }
    }

    /// Start the WebRTC store (connect to relays, begin peer discovery)
    pub async fn start(&mut self, keys: Keys) -> Result<(), WebRTCStoreError> {
        // Update peer ID with actual pubkey
        self.peer_id.pubkey = keys.public_key().to_hex();

        // Create Nostr client
        let client = Client::new(keys.clone());

        // Add relays
        for relay in &self.config.relays {
            client
                .add_relay(relay)
                .await
                .map_err(|e| WebRTCStoreError::Nostr(e.to_string()))?;
        }

        // Connect to relays
        client.connect().await;

        self.client = Some(client.clone());
        *self.running.write().await = true;

        // Subscribe to hashtree signaling events
        let filter = Filter::new()
            .kind(Kind::Custom(NOSTR_KIND_HASHTREE))
            .since(Timestamp::now());

        client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| WebRTCStoreError::Nostr(e.to_string()))?;

        // Send initial hello
        self.send_hello().await?;

        // Start background tasks
        self.start_event_handler(client.clone()).await;
        self.start_signaling_sender(client).await;
        self.start_hello_timer().await;

        Ok(())
    }

    /// Send hello message to discover peers
    async fn send_hello(&self) -> Result<(), WebRTCStoreError> {
        let roots: Vec<String> = self.config.roots.iter().map(to_hex).collect();

        let msg = SignalingMessage::Hello {
            peer_id: self.peer_id.to_peer_string(),
            roots,
        };

        self.signaling_tx
            .send(msg)
            .await
            .map_err(|_| WebRTCStoreError::Nostr("Channel closed".to_string()))?;

        Ok(())
    }

    /// Start event handler for incoming Nostr events
    async fn start_event_handler(&self, client: Client) {
        let peers = self.peers.clone();
        let peer_roots = self.peer_roots.clone();
        let local_peer_id = self.peer_id.to_peer_string();
        let signaling_tx = self.signaling_tx.clone();
        let local_store = self.local_store.clone();
        let running = self.running.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            loop {
                if !*running.read().await {
                    break;
                }

                // Handle notifications
                if let Ok(notification) =
                    tokio::time::timeout(std::time::Duration::from_millis(100), client.notifications().recv()).await
                {
                    match notification {
                        Ok(RelayPoolNotification::Event { event, .. }) => {
                            if event.kind == Kind::Custom(NOSTR_KIND_HASHTREE) {
                                if config.debug {
                                    let content_preview = if event.content.len() > 80 {
                                        format!("{}...", &event.content[..80])
                                    } else {
                                        event.content.clone()
                                    };
                                    println!("[Store] Received event: {}", content_preview);
                                }
                                match serde_json::from_str::<SignalingMessage>(&event.content) {
                                    Ok(msg) => {
                                        Self::handle_signaling_message(
                                            msg,
                                            &local_peer_id,
                                            peers.clone(),
                                            peer_roots.clone(),
                                            signaling_tx.clone(),
                                            local_store.clone(),
                                            &config,
                                            stats.clone(),
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        if config.debug {
                                            println!("[Store] Failed to parse signaling message: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(RelayPoolNotification::Message { relay_url, message }) => {
                            if config.debug {
                                if let nostr_sdk::RelayMessage::Notice { message: notice } = message {
                                    println!("[Store] NOTICE from {}: {}", relay_url, notice);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    /// Handle incoming signaling message
    async fn handle_signaling_message(
        msg: SignalingMessage,
        local_peer_id: &str,
        peers: Arc<RwLock<HashMap<String, Arc<Peer<S>>>>>,
        peer_roots: Arc<RwLock<HashMap<String, Vec<String>>>>,
        signaling_tx: mpsc::Sender<SignalingMessage>,
        local_store: Arc<S>,
        config: &WebRTCStoreConfig,
        stats: Arc<RwLock<WebRTCStats>>,
    ) {
        match &msg {
            SignalingMessage::Hello { peer_id, roots } => {
                if peer_id == local_peer_id {
                    return; // Ignore own messages
                }

                if config.debug {
                    println!("[Store] Received hello from {}", peer_id);
                }

                // Store peer roots
                peer_roots.write().await.insert(peer_id.clone(), roots.clone());

                // Initiate connection if we need more peers
                // Use deterministic tie-breaker: lower peer_id initiates connection
                let peer_count = peers.read().await.len();
                let should_initiate = local_peer_id < peer_id.as_str();

                if peer_count < config.satisfied_connections && should_initiate {
                    if let Some(remote_id) = PeerId::from_peer_string(peer_id) {
                        if !peers.read().await.contains_key(peer_id) {
                            if config.debug {
                                println!("[Store] Initiating connection to {}", peer_id);
                            }
                            if let Ok(peer) = Peer::new(
                                remote_id,
                                local_peer_id.to_string(),
                                signaling_tx.clone(),
                                local_store.clone(),
                                config.debug,
                            )
                            .await
                            {
                                let peer = Arc::new(peer);
                                if peer.connect().await.is_ok() {
                                    peers.write().await.insert(peer_id.clone(), peer);
                                    stats.write().await.connected_peers += 1;
                                }
                            }
                        }
                    }
                }
            }
            SignalingMessage::Offer {
                peer_id,
                target_peer_id,
                ..
            }
            | SignalingMessage::Answer {
                peer_id,
                target_peer_id,
                ..
            }
            | SignalingMessage::Candidate {
                peer_id,
                target_peer_id,
                ..
            }
            | SignalingMessage::Candidates {
                peer_id,
                target_peer_id,
                ..
            } => {
                if target_peer_id != local_peer_id {
                    return; // Not for us
                }

                // Get or create peer
                let peer = {
                    let peers_read = peers.read().await;
                    peers_read.get(peer_id).cloned()
                };

                let peer = match peer {
                    Some(p) => p,
                    None => {
                        if let Some(remote_id) = PeerId::from_peer_string(peer_id) {
                            if peers.read().await.len() < config.max_connections {
                                if let Ok(p) = Peer::new(
                                    remote_id,
                                    local_peer_id.to_string(),
                                    signaling_tx.clone(),
                                    local_store.clone(),
                                    config.debug,
                                )
                                .await
                                {
                                    let p = Arc::new(p);
                                    peers.write().await.insert(peer_id.clone(), p.clone());
                                    stats.write().await.connected_peers += 1;
                                    p
                                } else {
                                    return;
                                }
                            } else {
                                return;
                            }
                        } else {
                            return;
                        }
                    }
                };

                let _ = peer.handle_signaling(msg).await;
            }
        }
    }

    /// Start signaling message sender
    async fn start_signaling_sender(&self, client: Client) {
        let mut rx = self.signaling_rx.write().await.take().unwrap();
        let running = self.running.clone();

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if !*running.read().await {
                    break;
                }

                let json = serde_json::to_string(&msg).unwrap();
                println!("[Store] Sending signaling: {}", &json[..json.len().min(100)]);
                let builder =
                    EventBuilder::new(Kind::Custom(NOSTR_KIND_HASHTREE), json, []);

                let _ = client.send_event_builder(builder).await;
            }
        });
    }

    /// Start periodic hello sender
    async fn start_hello_timer(&self) {
        let signaling_tx = self.signaling_tx.clone();
        let peer_id = self.peer_id.to_peer_string();
        let roots: Vec<String> = self.config.roots.iter().map(to_hex).collect();
        let interval_ms = self.config.hello_interval_ms;
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_millis(interval_ms));

            loop {
                interval.tick().await;

                if !*running.read().await {
                    break;
                }

                let msg = SignalingMessage::Hello {
                    peer_id: peer_id.clone(),
                    roots: roots.clone(),
                };

                let _ = signaling_tx.send(msg).await;
            }
        });
    }

    /// Stop the WebRTC store
    pub async fn stop(&self) {
        *self.running.write().await = false;

        // Close all peer connections
        let peers = self.peers.read().await;
        for peer in peers.values() {
            let _ = peer.close().await;
        }

        // Disconnect from relays
        if let Some(ref client) = self.client {
            let _ = client.disconnect().await;
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> WebRTCStats {
        self.stats.read().await.clone()
    }

    /// Get connected peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        let mut count = 0;
        for peer in peers.values() {
            if peer.state().await == PeerState::Ready {
                count += 1;
            }
        }
        count
    }

    /// Request data from peers
    async fn request_from_peers(&self, hash: &Hash) -> Result<Option<Vec<u8>>, WebRTCStoreError> {
        let peers = self.peers.read().await;

        // Try each ready peer
        for peer in peers.values() {
            if peer.state().await == PeerState::Ready {
                match peer.request(hash).await {
                    Ok(Some(data)) => {
                        // Verify hash
                        if hashtree_core::sha256(&data) == *hash {
                            // Store locally for future requests
                            let _ = self.local_store.put(*hash, data.clone()).await;
                            let mut stats = self.stats.write().await;
                            stats.requests_fulfilled += 1;
                            stats.bytes_received += data.len() as u64;
                            return Ok(Some(data));
                        }
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl<S: Store + 'static> Store for WebRTCStore<S> {
    async fn put(&self, hash: Hash, data: Vec<u8>) -> Result<bool, StoreError> {
        self.local_store.put(hash, data).await
    }

    async fn get(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        // Try local first
        if let Some(data) = self.local_store.get(hash).await? {
            return Ok(Some(data));
        }

        // Update stats
        self.stats.write().await.requests_made += 1;

        // Try peers
        match self.request_from_peers(hash).await {
            Ok(data) => Ok(data),
            Err(_) => Ok(None),
        }
    }

    async fn has(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local_store.has(hash).await
    }

    async fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.local_store.delete(hash).await
    }
}
