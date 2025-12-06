//! WebRTC peer connection for hashtree data exchange

use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::ice::udp_network::{EphemeralUDP, UDPNetwork};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use super::types::{DataMessage, PeerDirection, PeerId, SignalingMessage};

/// Trait for content storage that can be used by WebRTC peers
pub trait ContentStore: Send + Sync + 'static {
    /// Get content by hex hash
    fn get(&self, hash_hex: &str) -> Result<Option<Vec<u8>>>;
}

/// Pending request tracking
struct PendingRequest {
    hash: String,
    response_tx: oneshot::Sender<Option<Vec<u8>>>,
}

/// WebRTC peer connection with data channel protocol
pub struct Peer {
    pub peer_id: PeerId,
    pub direction: PeerDirection,
    pub created_at: std::time::Instant,
    pub connected_at: Option<std::time::Instant>,

    pc: Arc<RTCPeerConnection>,
    data_channel: Option<Arc<RTCDataChannel>>,
    signaling_tx: mpsc::Sender<SignalingMessage>,
    my_peer_id: PeerId,

    // Content store for serving requests
    store: Option<Arc<dyn ContentStore>>,

    // Track pending outgoing requests
    pending_requests: Arc<Mutex<HashMap<u32, PendingRequest>>>,
    next_request_id: Arc<std::sync::atomic::AtomicU32>,

    // Channel for incoming data messages
    message_tx: mpsc::Sender<(DataMessage, Option<Vec<u8>>)>,
    message_rx: Option<mpsc::Receiver<(DataMessage, Option<Vec<u8>>)>>,
}

impl Peer {
    /// Create a new peer connection
    pub async fn new(
        peer_id: PeerId,
        direction: PeerDirection,
        my_peer_id: PeerId,
        signaling_tx: mpsc::Sender<SignalingMessage>,
        stun_servers: Vec<String>,
    ) -> Result<Self> {
        Self::new_with_store(peer_id, direction, my_peer_id, signaling_tx, stun_servers, None).await
    }

    /// Create a new peer connection with content store
    pub async fn new_with_store(
        peer_id: PeerId,
        direction: PeerDirection,
        my_peer_id: PeerId,
        signaling_tx: mpsc::Sender<SignalingMessage>,
        stun_servers: Vec<String>,
        store: Option<Arc<dyn ContentStore>>,
    ) -> Result<Self> {
        // Create WebRTC API
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;

        let mut se = SettingEngine::default();
        let ephemeral = EphemeralUDP::new(10000, 10099)?;
        se.set_udp_network(UDPNetwork::Ephemeral(ephemeral));

        let api = APIBuilder::new()
            .with_setting_engine(se)
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();

        // Configure ICE servers
        let ice_servers: Vec<RTCIceServer> = stun_servers
            .iter()
            .map(|url| RTCIceServer {
                urls: vec![url.clone()],
                ..Default::default()
            })
            .collect();

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let pc = Arc::new(api.new_peer_connection(config).await?);
        let (message_tx, message_rx) = mpsc::channel(100);

        Ok(Self {
            peer_id,
            direction,
            created_at: std::time::Instant::now(),
            connected_at: None,
            pc,
            data_channel: None,
            signaling_tx,
            my_peer_id,
            store,
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            message_tx,
            message_rx: Some(message_rx),
        })
    }

    /// Set content store
    pub fn set_store(&mut self, store: Arc<dyn ContentStore>) {
        self.store = Some(store);
    }

    /// Get connection state
    pub fn state(&self) -> RTCPeerConnectionState {
        self.pc.connection_state()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }

    /// Setup event handlers for the peer connection
    pub async fn setup_handlers(&mut self) -> Result<()> {
        let peer_id = self.peer_id.clone();
        let signaling_tx = self.signaling_tx.clone();
        let my_uuid = self.my_peer_id.uuid.clone();
        let recipient = self.peer_id.to_string();

        // Handle ICE candidates
        self.pc
            .on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
                let signaling_tx = signaling_tx.clone();
                let my_uuid = my_uuid.clone();
                let recipient = recipient.clone();

                Box::pin(async move {
                    if let Some(c) = candidate {
                        if let Some(init) = c.to_json().ok() {
                            info!("ICE candidate generated: {}", &init.candidate[..init.candidate.len().min(60)]);
                            let msg = SignalingMessage::candidate(
                                serde_json::to_value(&init).unwrap_or_default(),
                                &recipient,
                                &my_uuid,
                            );
                            if let Err(e) = signaling_tx.send(msg).await {
                                error!("Failed to send ICE candidate: {}", e);
                            } else {
                                info!("Queued ICE candidate for {}", recipient);
                            }
                        }
                    }
                })
            }));

        // Handle connection state changes
        let peer_id_log = peer_id.clone();
        self.pc
            .on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
                let peer_id = peer_id_log.clone();
                Box::pin(async move {
                    info!("Peer {} connection state: {:?}", peer_id.short(), state);
                })
            }));

        Ok(())
    }

    /// Initiate connection (create offer) - for outbound connections
    pub async fn connect(&mut self) -> Result<serde_json::Value> {
        // Create data channel first
        let dc = self.pc.create_data_channel("hashtree", None).await?;
        self.setup_data_channel(dc.clone()).await?;
        self.data_channel = Some(dc);

        // Create offer
        let offer = self.pc.create_offer(None).await?;
        self.pc.set_local_description(offer.clone()).await?;

        // Return offer as JSON
        let offer_json = serde_json::json!({
            "type": offer.sdp_type.to_string().to_lowercase(),
            "sdp": offer.sdp
        });

        Ok(offer_json)
    }

    /// Handle incoming offer and create answer
    pub async fn handle_offer(&mut self, offer: serde_json::Value) -> Result<serde_json::Value> {
        let sdp = offer
            .get("sdp")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing SDP in offer"))?;

        let offer_desc = RTCSessionDescription::offer(sdp.to_string())?;
        self.pc.set_remote_description(offer_desc).await?;

        // Setup data channel handler for incoming channels
        let peer_id = self.peer_id.clone();
        let message_tx = self.message_tx.clone();
        let pending_requests = self.pending_requests.clone();
        let store = self.store.clone();

        self.pc
            .on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let peer_id = peer_id.clone();
                let message_tx = message_tx.clone();
                let pending_requests = pending_requests.clone();
                let store = store.clone();

                Box::pin(async move {
                    info!("Peer {} received data channel: {}", peer_id.short(), dc.label());

                    // Set up message handlers
                    Self::setup_dc_handlers(
                        dc.clone(),
                        peer_id,
                        message_tx,
                        pending_requests,
                        store,
                    )
                    .await;
                })
            }));

        // Create answer
        let answer = self.pc.create_answer(None).await?;
        self.pc.set_local_description(answer.clone()).await?;

        let answer_json = serde_json::json!({
            "type": answer.sdp_type.to_string().to_lowercase(),
            "sdp": answer.sdp
        });

        Ok(answer_json)
    }

    /// Handle incoming answer
    pub async fn handle_answer(&mut self, answer: serde_json::Value) -> Result<()> {
        let sdp = answer
            .get("sdp")
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing SDP in answer"))?;

        let answer_desc = RTCSessionDescription::answer(sdp.to_string())?;
        self.pc.set_remote_description(answer_desc).await?;

        Ok(())
    }

    /// Handle incoming ICE candidate
    pub async fn handle_candidate(&mut self, candidate: serde_json::Value) -> Result<()> {
        let candidate_str = candidate
            .get("candidate")
            .and_then(|c| c.as_str())
            .unwrap_or("");

        let sdp_mid = candidate
            .get("sdpMid")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string());

        let sdp_mline_index = candidate
            .get("sdpMLineIndex")
            .and_then(|i| i.as_u64())
            .map(|i| i as u16);

        if !candidate_str.is_empty() {
            use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
            let init = RTCIceCandidateInit {
                candidate: candidate_str.to_string(),
                sdp_mid,
                sdp_mline_index,
                username_fragment: candidate
                    .get("usernameFragment")
                    .and_then(|u| u.as_str())
                    .map(|s| s.to_string()),
            };
            self.pc.add_ice_candidate(init).await?;
        }

        Ok(())
    }

    /// Setup data channel handlers
    async fn setup_data_channel(&mut self, dc: Arc<RTCDataChannel>) -> Result<()> {
        let peer_id = self.peer_id.clone();
        let message_tx = self.message_tx.clone();
        let pending_requests = self.pending_requests.clone();
        let store = self.store.clone();

        Self::setup_dc_handlers(dc, peer_id, message_tx, pending_requests, store).await;
        Ok(())
    }

    /// Setup handlers for a data channel (shared between outbound and inbound)
    async fn setup_dc_handlers(
        dc: Arc<RTCDataChannel>,
        peer_id: PeerId,
        message_tx: mpsc::Sender<(DataMessage, Option<Vec<u8>>)>,
        pending_requests: Arc<Mutex<HashMap<u32, PendingRequest>>>,
        store: Option<Arc<dyn ContentStore>>,
    ) {
        let label = dc.label().to_string();
        let peer_short = peer_id.short();

        // Track pending binary data (request_id -> expected after response)
        let pending_binary: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));

        let dc_for_open = dc.clone();
        let peer_short_open = peer_short.clone();
        dc.on_open(Box::new(move || {
            info!("[Peer {}] Data channel '{}' open", peer_short_open, label);
            Box::pin(async {})
        }));

        let dc_for_msg = dc.clone();
        let peer_short_msg = peer_short.clone();
        let pending_binary_clone = pending_binary.clone();
        let store_clone = store.clone();

        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let dc = dc_for_msg.clone();
            let peer_short = peer_short_msg.clone();
            let pending_requests = pending_requests.clone();
            let pending_binary = pending_binary_clone.clone();
            let message_tx = message_tx.clone();
            let store = store_clone.clone();

            Box::pin(async move {
                if msg.is_string {
                    // JSON message
                    if let Ok(text) = String::from_utf8(msg.data.to_vec()) {
                        trace!("[Peer {}] Received JSON: {}", peer_short, text);

                        if let Ok(data_msg) = serde_json::from_str::<DataMessage>(&text) {
                            match &data_msg {
                                DataMessage::Request { id, hash } => {
                                    debug!(
                                        "[Peer {}] Received request {} for {}",
                                        peer_short, id, &hash[..8.min(hash.len())]
                                    );

                                    // Handle request - look up in store
                                    let (found, data) = if let Some(ref store) = store {
                                        match store.get(hash) {
                                            Ok(Some(data)) => (true, Some(data)),
                                            Ok(None) => (false, None),
                                            Err(e) => {
                                                warn!("[Peer {}] Store error: {}", peer_short, e);
                                                (false, None)
                                            }
                                        }
                                    } else {
                                        (false, None)
                                    };

                                    // Send response
                                    let response = DataMessage::Response {
                                        id: *id,
                                        hash: hash.clone(),
                                        found,
                                    };
                                    if let Ok(json) = serde_json::to_string(&response) {
                                        if let Err(e) = dc.send_text(json).await {
                                            error!(
                                                "[Peer {}] Failed to send response: {}",
                                                peer_short, e
                                            );
                                        }
                                    }

                                    // Send binary data if found
                                    if let Some(data) = data {
                                        // Format: [4 bytes request_id (little-endian)][data]
                                        let mut packet = Vec::with_capacity(4 + data.len());
                                        packet.extend_from_slice(&id.to_le_bytes());
                                        packet.extend_from_slice(&data);

                                        if let Err(e) = dc.send(&Bytes::from(packet)).await {
                                            error!(
                                                "[Peer {}] Failed to send binary data: {}",
                                                peer_short, e
                                            );
                                        } else {
                                            debug!(
                                                "[Peer {}] Sent {} bytes for request {}",
                                                peer_short,
                                                data.len(),
                                                id
                                            );
                                        }
                                    }
                                }
                                DataMessage::Response { id, hash, found } => {
                                    debug!(
                                        "[Peer {}] Received response {} for {}: found={}",
                                        peer_short,
                                        id,
                                        &hash[..8.min(hash.len())],
                                        found
                                    );

                                    if *found {
                                        // Expect binary data next
                                        *pending_binary.lock().await = Some(*id);
                                    } else {
                                        // Not found - resolve request with None
                                        let mut pending = pending_requests.lock().await;
                                        if let Some(req) = pending.remove(id) {
                                            let _ = req.response_tx.send(None);
                                        }
                                    }
                                }
                                _ => {
                                    // Forward other messages
                                    let _ = message_tx.send((data_msg, None)).await;
                                }
                            }
                        }
                    }
                } else {
                    // Binary message - should follow a response with found=true
                    let data = msg.data.to_vec();
                    trace!("[Peer {}] Received {} bytes binary", peer_short, data.len());

                    if data.len() >= 4 {
                        // Extract request ID
                        let request_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                        let payload = data[4..].to_vec();

                        debug!(
                            "[Peer {}] Binary data for request {}: {} bytes",
                            peer_short,
                            request_id,
                            payload.len()
                        );

                        // Resolve the pending request
                        let mut pending = pending_requests.lock().await;
                        if let Some(req) = pending.remove(&request_id) {
                            // TODO: Verify hash matches
                            let _ = req.response_tx.send(Some(payload));
                        }

                        // Clear pending binary
                        *pending_binary.lock().await = None;
                    }
                }
            })
        }));
    }

    /// Check if data channel is ready
    pub fn has_data_channel(&self) -> bool {
        self.data_channel.is_some()
    }

    /// Request content by hash from this peer
    pub async fn request(&self, hash_hex: &str) -> Result<Option<Vec<u8>>> {
        let dc = self
            .data_channel
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No data channel"))?;

        let request_id = self
            .next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Store pending request
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(
                request_id,
                PendingRequest {
                    hash: hash_hex.to_string(),
                    response_tx: tx,
                },
            );
        }

        // Send request
        let request = DataMessage::Request {
            id: request_id,
            hash: hash_hex.to_string(),
        };
        let json = serde_json::to_string(&request)?;
        dc.send_text(json).await?;

        debug!(
            "[Peer {}] Sent request {} for {}",
            self.peer_id.short(),
            request_id,
            &hash_hex[..8.min(hash_hex.len())]
        );

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(data)) => Ok(data),
            Ok(Err(_)) => {
                // Channel closed
                Ok(None)
            }
            Err(_) => {
                // Timeout - clean up pending request
                let mut pending = self.pending_requests.lock().await;
                pending.remove(&request_id);
                Ok(None)
            }
        }
    }

    /// Send a JSON message over the data channel
    pub async fn send_message(&self, msg: &DataMessage) -> Result<()> {
        if let Some(ref dc) = self.data_channel {
            let json = serde_json::to_string(msg)?;
            dc.send_text(json).await?;
        }
        Ok(())
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        if let Some(ref dc) = self.data_channel {
            dc.close().await?;
        }
        self.pc.close().await?;
        Ok(())
    }
}
