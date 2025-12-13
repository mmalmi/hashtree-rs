//! WebRTC peer connection management
//!
//! Handles WebRTC connection establishment, data channel communication,
//! and the request/response protocol for hash-based data exchange.

use crate::types::{DataMessage, PeerId, PeerState, SignalingMessage, DATA_CHANNEL_LABEL};
use bytes::Bytes;
use hashtree::{from_hex, to_hex, Hash, Store};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, RwLock};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("WebRTC error: {0}")]
    WebRTC(#[from] webrtc::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Request timeout")]
    Timeout,
    #[error("Peer not ready")]
    NotReady,
    #[error("Data not found")]
    NotFound,
}

/// Default LRU cache sizes (matching hashtree-ts)
const THEIR_REQUESTS_SIZE: usize = 200;

/// Pending request awaiting response (requests WE sent)
struct PendingRequest {
    response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// Request this peer sent TO US that we couldn't fulfill locally
/// We track it so we can push data back when/if we get it from another peer
#[derive(Debug, Clone)]
struct TheirRequest {
    /// Their request ID (for response correlation)
    id: u32,
    /// When they requested it
    requested_at: std::time::Instant,
}

/// WebRTC peer connection wrapper
///
/// Each Peer is an independent agent that tracks:
/// - `pending_requests`: requests WE sent TO this peer (awaiting response)
/// - `their_requests`: requests THEY sent TO US that we couldn't fulfill
///
/// This matches the hashtree-ts Peer architecture.
pub struct Peer<S: Store> {
    /// Remote peer identifier
    pub remote_id: PeerId,
    /// Connection state
    state: Arc<RwLock<PeerState>>,
    /// WebRTC peer connection
    connection: Arc<RTCPeerConnection>,
    /// Data channel (when established)
    data_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    /// Pending ICE candidates (before remote description set)
    pending_candidates: Arc<RwLock<Vec<RTCIceCandidateInit>>>,
    /// Requests WE sent TO this peer, keyed by our request ID
    /// Similar to hashtree-ts: ourRequests = new Map<number, OurRequest>()
    pending_requests: Arc<RwLock<HashMap<u32, PendingRequest>>>,
    /// Requests THEY sent TO US that we couldn't fulfill locally
    /// Keyed by hash hex string, similar to hashtree-ts:
    /// theirRequests = new LRUCache<string, TheirRequest>(THEIR_REQUESTS_SIZE)
    their_requests: Arc<RwLock<LruCache<String, TheirRequest>>>,
    /// Request ID counter
    request_counter: AtomicU32,
    /// Channel for outgoing signaling messages
    signaling_tx: mpsc::Sender<SignalingMessage>,
    /// Local store for responding to requests
    local_store: Arc<S>,
    /// Local peer ID
    local_peer_id: String,
    /// Debug logging enabled
    debug: bool,
    /// Callback to forward request to other peers when we don't have data locally
    on_forward_request: Option<Arc<dyn Fn(Hash, PeerId) -> futures::future::BoxFuture<'static, Option<Vec<u8>>> + Send + Sync>>,
}

impl<S: Store + 'static> Peer<S> {
    /// Create a new peer connection
    pub async fn new(
        remote_id: PeerId,
        local_peer_id: String,
        signaling_tx: mpsc::Sender<SignalingMessage>,
        local_store: Arc<S>,
        debug: bool,
    ) -> Result<Self, PeerError> {
        // Create WebRTC API
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        // Configure ICE servers (matches hashtree-ts)
        let config = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec![
                    "stun:stun.iris.to:3478".to_string(),
                    "stun:stun.l.google.com:19302".to_string(),
                    "stun:stun.cloudflare.com:3478".to_string(),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let connection = Arc::new(api.new_peer_connection(config).await?);

        let peer = Self {
            remote_id,
            state: Arc::new(RwLock::new(PeerState::New)),
            connection,
            data_channel: Arc::new(RwLock::new(None)),
            pending_candidates: Arc::new(RwLock::new(Vec::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            their_requests: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(THEIR_REQUESTS_SIZE).unwrap(),
            ))),
            request_counter: AtomicU32::new(0),
            signaling_tx,
            local_store,
            local_peer_id,
            debug,
            on_forward_request: None,
        };

        peer.setup_handlers().await?;

        Ok(peer)
    }

    /// Setup connection event handlers
    async fn setup_handlers(&self) -> Result<(), PeerError> {
        let state = self.state.clone();
        let data_channel = self.data_channel.clone();
        let pending_requests = self.pending_requests.clone();
        let their_requests = self.their_requests.clone();
        let local_store = self.local_store.clone();
        let debug = self.debug;

        // Handle connection state changes
        let state_clone = state.clone();
        self.connection
            .on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
                let state = state_clone.clone();
                Box::pin(async move {
                    let mut state = state.write().await;
                    match s {
                        RTCPeerConnectionState::Connected => {
                            *state = PeerState::Connected;
                            if debug {
                                println!("[Peer] Connection established");
                            }
                        }
                        RTCPeerConnectionState::Disconnected
                        | RTCPeerConnectionState::Failed
                        | RTCPeerConnectionState::Closed => {
                            *state = PeerState::Disconnected;
                            if debug {
                                println!("[Peer] Connection closed: {:?}", s);
                            }
                        }
                        _ => {}
                    }
                })
            }));

        // Handle incoming data channels
        let data_channel_clone = data_channel.clone();
        let pending_requests_clone = pending_requests.clone();
        let their_requests_clone = their_requests.clone();
        let local_store_clone = local_store.clone();
        let state_clone = state.clone();
        self.connection.on_data_channel(Box::new(move |dc| {
            let data_channel = data_channel_clone.clone();
            let pending_requests = pending_requests_clone.clone();
            let their_requests = their_requests_clone.clone();
            let local_store = local_store_clone.clone();
            let state = state_clone.clone();

            Box::pin(async move {
                if dc.label() == DATA_CHANNEL_LABEL {
                    Self::setup_data_channel_handlers(
                        dc.clone(),
                        pending_requests,
                        their_requests,
                        local_store,
                        debug,
                    )
                    .await;
                    *data_channel.write().await = Some(dc);
                    *state.write().await = PeerState::Ready;
                    if debug {
                        println!("[Peer] Data channel opened (incoming)");
                    }
                }
            })
        }));

        // Handle ICE candidates
        let signaling_tx = self.signaling_tx.clone();
        let local_peer_id = self.local_peer_id.clone();
        let remote_id = self.remote_id.to_peer_string();
        self.connection
            .on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
                let signaling_tx = signaling_tx.clone();
                let local_peer_id = local_peer_id.clone();
                let remote_id = remote_id.clone();

                Box::pin(async move {
                    if let Some(candidate) = candidate {
                        let json = candidate.to_json().unwrap();
                        let msg = SignalingMessage::Candidate {
                            peer_id: local_peer_id,
                            target_peer_id: remote_id,
                            candidate: json.candidate,
                            sdp_m_line_index: json.sdp_mline_index,
                            sdp_mid: json.sdp_mid,
                        };
                        let _ = signaling_tx.send(msg).await;
                    }
                })
            }));

        Ok(())
    }

    /// Setup handlers for a data channel
    async fn setup_data_channel_handlers(
        dc: Arc<RTCDataChannel>,
        pending_requests: Arc<RwLock<HashMap<u32, PendingRequest>>>,
        their_requests: Arc<RwLock<LruCache<String, TheirRequest>>>,
        local_store: Arc<S>,
        debug: bool,
    ) {
        let pending_requests_clone = pending_requests.clone();
        let their_requests_clone = their_requests.clone();
        let local_store_clone = local_store.clone();
        let dc_clone = dc.clone();

        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let pending_requests = pending_requests_clone.clone();
            let their_requests = their_requests_clone.clone();
            let local_store = local_store_clone.clone();
            let dc = dc_clone.clone();

            Box::pin(async move {
                let data = msg.data.to_vec();
                if data.is_empty() {
                    return;
                }

                // Match hashtree-ts: distinguish by whether it's valid UTF-8 JSON
                // - String/JSON: control messages (req, res, have, want, root)
                // - Binary: [4 bytes requestId LE][data]
                if let Ok(json_str) = std::str::from_utf8(&data) {
                    // JSON message
                    if let Ok(msg) = serde_json::from_str::<DataMessage>(json_str) {
                        match msg {
                            DataMessage::Response {
                                id, found, hash, ..
                            } => {
                                if !found {
                                    let mut requests = pending_requests.write().await;
                                    if let Some(request) = requests.remove(&id) {
                                        let _ = request.response_tx.send(None);
                                    }
                                }
                                // If found, binary data follows in separate message
                                if debug {
                                    println!(
                                        "[Peer] Response: id={}, hash={}, found={}",
                                        id, hash, found
                                    );
                                }
                            }
                            DataMessage::Request { id, hash } => {
                                if debug {
                                    println!("[Peer] Request: id={}, hash={}", id, hash);
                                }
                                // Look up data in local store and respond
                                if let Ok(hash_bytes) = from_hex(&hash) {
                                    let response = match local_store.get(&hash_bytes).await {
                                        Ok(Some(payload)) => {
                                            if debug {
                                                println!("[Peer] Responding with {} bytes", payload.len());
                                            }
                                            // Send JSON response header
                                            let res_msg = DataMessage::Response {
                                                id,
                                                hash: hash.clone(),
                                                found: true,
                                                size: Some(payload.len() as u64),
                                            };
                                            let json = serde_json::to_string(&res_msg).unwrap();
                                            let _ = dc.send(&Bytes::from(json)).await;

                                            // Send binary data: [4 bytes requestId LE][data]
                                            let mut binary = Vec::with_capacity(4 + payload.len());
                                            binary.extend_from_slice(&id.to_le_bytes());
                                            binary.extend_from_slice(&payload);
                                            let _ = dc.send(&Bytes::from(binary)).await;
                                            true
                                        }
                                        _ => false,
                                    };
                                    if !response {
                                        // Track this request so we can push data later
                                        // (like hashtree-ts theirRequests)
                                        {
                                            let mut their_reqs = their_requests.write().await;
                                            their_reqs.put(
                                                hash.clone(),
                                                TheirRequest {
                                                    id,
                                                    requested_at: std::time::Instant::now(),
                                                },
                                            );
                                        }

                                        // Send not found response
                                        let res_msg = DataMessage::Response {
                                            id,
                                            hash,
                                            found: false,
                                            size: None,
                                        };
                                        let json = serde_json::to_string(&res_msg).unwrap();
                                        let _ = dc.send(&Bytes::from(json)).await;
                                    }
                                }
                            }
                            DataMessage::Push { hash } => {
                                // Peer is pushing data we previously requested
                                if debug {
                                    println!("[Peer] Received push for hash: {}...", &hash[..16.min(hash.len())]);
                                }
                                // Binary data will follow - handled in binary message section
                            }
                            _ => {}
                        }
                    }
                } else {
                    // Binary data: [4 bytes requestId little-endian][data]
                    // Matches hashtree-ts format
                    if data.len() < 4 {
                        return;
                    }
                    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let payload = data[4..].to_vec();

                    let mut requests = pending_requests.write().await;
                    if let Some(request) = requests.remove(&id) {
                        let _ = request.response_tx.send(Some(payload));
                    }
                }
            })
        }));
    }

    /// Initiate connection as offerer
    pub async fn connect(&self) -> Result<(), PeerError> {
        *self.state.write().await = PeerState::Connecting;

        // Create data channel
        // Use unordered for better performance - protocol is stateless (each message self-describes)
        let dc_init = RTCDataChannelInit {
            ordered: Some(false),
            ..Default::default()
        };
        let dc = self
            .connection
            .create_data_channel(DATA_CHANNEL_LABEL, Some(dc_init))
            .await?;

        Self::setup_data_channel_handlers(
            dc.clone(),
            self.pending_requests.clone(),
            self.their_requests.clone(),
            self.local_store.clone(),
            self.debug,
        )
        .await;

        let data_channel = self.data_channel.clone();
        let state = self.state.clone();
        let debug = self.debug;
        dc.on_open(Box::new(move || {
            let _data_channel = data_channel.clone();
            let state = state.clone();

            Box::pin(async move {
                *state.write().await = PeerState::Ready;
                if debug {
                    println!("[Peer] Data channel opened (outgoing)");
                }
            })
        }));

        *self.data_channel.write().await = Some(dc);

        // Create and send offer
        let offer = self.connection.create_offer(None).await?;
        self.connection.set_local_description(offer.clone()).await?;

        let msg = SignalingMessage::Offer {
            peer_id: self.local_peer_id.clone(),
            target_peer_id: self.remote_id.to_peer_string(),
            sdp: offer.sdp,
        };
        self.signaling_tx
            .send(msg)
            .await
            .map_err(|_| PeerError::ChannelClosed)?;

        Ok(())
    }

    /// Handle incoming signaling message
    pub async fn handle_signaling(&self, msg: SignalingMessage) -> Result<(), PeerError> {
        match msg {
            SignalingMessage::Offer { sdp, .. } => {
                let offer = RTCSessionDescription::offer(sdp)?;
                self.connection.set_remote_description(offer).await?;

                // Add any pending candidates
                let candidates = self.pending_candidates.write().await.drain(..).collect::<Vec<_>>();
                for candidate in candidates {
                    self.connection.add_ice_candidate(candidate).await?;
                }

                // Create and send answer
                let answer = self.connection.create_answer(None).await?;
                self.connection.set_local_description(answer.clone()).await?;

                let msg = SignalingMessage::Answer {
                    peer_id: self.local_peer_id.clone(),
                    target_peer_id: self.remote_id.to_peer_string(),
                    sdp: answer.sdp,
                };
                self.signaling_tx
                    .send(msg)
                    .await
                    .map_err(|_| PeerError::ChannelClosed)?;

                *self.state.write().await = PeerState::Connecting;
            }
            SignalingMessage::Answer { sdp, .. } => {
                let answer = RTCSessionDescription::answer(sdp)?;
                self.connection.set_remote_description(answer).await?;

                // Add any pending candidates
                let candidates = self.pending_candidates.write().await.drain(..).collect::<Vec<_>>();
                for candidate in candidates {
                    self.connection.add_ice_candidate(candidate).await?;
                }
            }
            SignalingMessage::Candidate {
                candidate,
                sdp_m_line_index,
                sdp_mid,
                ..
            } => {
                let init = RTCIceCandidateInit {
                    candidate,
                    sdp_mid,
                    sdp_mline_index: sdp_m_line_index,
                    ..Default::default()
                };

                // Check if remote description is set
                if self.connection.remote_description().await.is_some() {
                    self.connection.add_ice_candidate(init).await?;
                } else {
                    self.pending_candidates.write().await.push(init);
                }
            }
            SignalingMessage::Candidates { candidates, .. } => {
                for c in candidates {
                    let init = RTCIceCandidateInit {
                        candidate: c.candidate,
                        sdp_mid: c.sdp_mid,
                        sdp_mline_index: c.sdp_m_line_index,
                        ..Default::default()
                    };

                    if self.connection.remote_description().await.is_some() {
                        self.connection.add_ice_candidate(init).await?;
                    } else {
                        self.pending_candidates.write().await.push(init);
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Request data by hash
    pub async fn request(&self, hash: &Hash) -> Result<Option<Vec<u8>>, PeerError> {
        let state = *self.state.read().await;
        if state != PeerState::Ready {
            return Err(PeerError::NotReady);
        }

        let dc = self.data_channel.read().await;
        let dc = dc.as_ref().ok_or(PeerError::NotReady)?;

        let id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        let hash_hex = to_hex(hash);

        // Setup response channel
        let (tx, rx) = oneshot::channel();
        self.pending_requests
            .write()
            .await
            .insert(id, PendingRequest { response_tx: tx });

        // Send request as JSON string (matches hashtree-ts)
        let msg = DataMessage::Request {
            id,
            hash: hash_hex.clone(),
        };
        let json = serde_json::to_string(&msg)?;
        dc.send(&Bytes::from(json)).await?;

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(data)) => Ok(data),
            Ok(Err(_)) => Err(PeerError::ChannelClosed),
            Err(_) => {
                // Remove pending request on timeout
                self.pending_requests.write().await.remove(&id);
                Err(PeerError::Timeout)
            }
        }
    }

    /// Send data response
    pub async fn send_response(
        &self,
        id: u32,
        hash: &Hash,
        data: Option<&[u8]>,
    ) -> Result<(), PeerError> {
        let dc = self.data_channel.read().await;
        let dc = dc.as_ref().ok_or(PeerError::NotReady)?;

        let hash_hex = to_hex(hash);

        if let Some(payload) = data {
            // Send JSON response header (as string, matches hashtree-ts)
            let msg = DataMessage::Response {
                id,
                hash: hash_hex,
                found: true,
                size: Some(payload.len() as u64),
            };
            let json = serde_json::to_string(&msg)?;
            dc.send(&Bytes::from(json)).await?;

            // Send binary data: [4 bytes requestId LE][data] (matches hashtree-ts)
            let mut binary = Vec::with_capacity(4 + payload.len());
            binary.extend_from_slice(&id.to_le_bytes());
            binary.extend_from_slice(payload);
            dc.send(&Bytes::from(binary)).await?;
        } else {
            let msg = DataMessage::Response {
                id,
                hash: hash_hex,
                found: false,
                size: None,
            };
            let json = serde_json::to_string(&msg)?;
            dc.send(&Bytes::from(json)).await?;
        }

        Ok(())
    }

    /// Get current connection state
    pub async fn state(&self) -> PeerState {
        *self.state.read().await
    }

    /// Close the connection
    pub async fn close(&self) -> Result<(), PeerError> {
        self.connection.close().await?;
        *self.state.write().await = PeerState::Disconnected;
        Ok(())
    }

    /// Set the forward request callback
    /// Called when this peer requests data we don't have locally
    pub fn set_on_forward_request<F>(&mut self, callback: F)
    where
        F: Fn(Hash, PeerId) -> futures::future::BoxFuture<'static, Option<Vec<u8>>> + Send + Sync + 'static,
    {
        self.on_forward_request = Some(Arc::new(callback));
    }

    /// Send data to this peer for a hash they previously requested
    /// Returns true if this peer had requested this hash
    pub async fn send_data(&self, hash_hex: &str, data: &[u8]) -> Result<bool, PeerError> {
        let their_req = {
            let mut requests = self.their_requests.write().await;
            requests.pop(hash_hex)
        };

        let Some(their_req) = their_req else {
            return Ok(false);
        };

        let dc = self.data_channel.read().await;
        let dc = dc.as_ref().ok_or(PeerError::NotReady)?;

        // Send push message followed by binary data (like hashtree-ts)
        let msg = DataMessage::Push {
            hash: hash_hex.to_string(),
        };
        let json = serde_json::to_string(&msg)?;
        dc.send(&Bytes::from(json)).await?;

        // Send binary data: [4 bytes requestId LE][data]
        let mut binary = Vec::with_capacity(4 + data.len());
        binary.extend_from_slice(&their_req.id.to_le_bytes());
        binary.extend_from_slice(data);
        dc.send(&Bytes::from(binary)).await?;

        if self.debug {
            println!("[Peer] Sent push data for hash: {}...", &hash_hex[..16.min(hash_hex.len())]);
        }

        Ok(true)
    }

    /// Check if this peer has requested a hash
    pub async fn has_requested(&self, hash_hex: &str) -> bool {
        self.their_requests.read().await.peek(hash_hex).is_some()
    }

    /// Get count of pending requests from this peer
    pub async fn their_request_count(&self) -> usize {
        self.their_requests.read().await.len()
    }

    /// Get count of pending requests we sent to this peer
    pub async fn our_request_count(&self) -> usize {
        self.pending_requests.read().await.len()
    }
}
