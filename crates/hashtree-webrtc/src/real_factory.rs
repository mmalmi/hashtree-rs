//! Real WebRTC peer connection factory
//!
//! Wraps the webrtc crate to implement PeerConnectionFactory for production use.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::transport::{DataChannel, PeerConnectionFactory, TransportError};
use crate::types::DATA_CHANNEL_LABEL;

use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Wrapper around RTCDataChannel that implements our DataChannel trait
struct RealDataChannel {
    dc: Arc<RTCDataChannel>,
}

#[async_trait]
impl DataChannel for RealDataChannel {
    async fn send(&self, data: Vec<u8>) -> Result<(), TransportError> {
        self.dc
            .send(&bytes::Bytes::from(data))
            .await
            .map(|_| ())
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        // Note: RTCDataChannel doesn't have a direct recv - it uses callbacks
        // This is a simplified implementation - in practice, messages come via on_message
        None
    }

    fn is_open(&self) -> bool {
        // Check data channel state
        self.dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
    }

    async fn close(&self) {
        let _ = self.dc.close().await;
    }
}

/// Pending connection state
struct PendingConnection {
    connection: Arc<RTCPeerConnection>,
    data_channel: Option<Arc<RTCDataChannel>>,
}

/// Real WebRTC peer connection factory
///
/// Creates actual WebRTC connections using the webrtc crate.
pub struct RealPeerConnectionFactory {
    /// Pending outbound connections (we sent offer, waiting for answer)
    pending: RwLock<HashMap<String, PendingConnection>>,
    /// Pending inbound connections (we received offer, sent answer)
    inbound: RwLock<HashMap<String, PendingConnection>>,
}

impl RealPeerConnectionFactory {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            inbound: RwLock::new(HashMap::new()),
        }
    }

    async fn create_connection() -> Result<Arc<RTCPeerConnection>, TransportError> {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

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

        api.new_peer_connection(config)
            .await
            .map(Arc::new)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }
}

impl Default for RealPeerConnectionFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PeerConnectionFactory for RealPeerConnectionFactory {
    async fn create_offer(
        &self,
        target_peer_id: &str,
    ) -> Result<(Arc<dyn DataChannel>, String), TransportError> {
        let connection = Self::create_connection().await?;

        // Create data channel
        let dc_init = RTCDataChannelInit {
            ordered: Some(false),
            ..Default::default()
        };
        let dc = connection
            .create_data_channel(DATA_CHANNEL_LABEL, Some(dc_init))
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Create offer
        let offer = connection
            .create_offer(None)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Store pending connection
        self.pending.write().await.insert(
            target_peer_id.to_string(),
            PendingConnection {
                connection,
                data_channel: Some(dc.clone()),
            },
        );

        let channel: Arc<dyn DataChannel> = Arc::new(RealDataChannel { dc });
        Ok((channel, offer.sdp))
    }

    async fn accept_offer(
        &self,
        from_peer_id: &str,
        offer_sdp: &str,
    ) -> Result<(Arc<dyn DataChannel>, String), TransportError> {
        let connection = Self::create_connection().await?;

        // Set remote description (the offer)
        let offer = RTCSessionDescription::offer(offer_sdp.to_string())
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        connection
            .set_remote_description(offer)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Create and set answer
        let answer = connection
            .create_answer(None)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        connection
            .set_local_description(answer.clone())
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Store for later - data channel will arrive via on_data_channel callback
        self.inbound.write().await.insert(
            from_peer_id.to_string(),
            PendingConnection {
                connection,
                data_channel: None,
            },
        );

        // Note: We need to wait for the data channel from the remote side
        // For now, return a placeholder - the real implementation would need
        // to set up callbacks and wait for the channel to be established
        // This is simplified for the trait interface
        Err(TransportError::ConnectionFailed(
            "Data channel not yet received - need to implement callback".to_string(),
        ))
    }

    async fn handle_answer(
        &self,
        target_peer_id: &str,
        answer_sdp: &str,
    ) -> Result<Arc<dyn DataChannel>, TransportError> {
        let pending = self
            .pending
            .write()
            .await
            .remove(target_peer_id)
            .ok_or_else(|| TransportError::ConnectionFailed("No pending connection".to_string()))?;

        // Set remote description (the answer)
        let answer = RTCSessionDescription::answer(answer_sdp.to_string())
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        pending
            .connection
            .set_remote_description(answer)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Return the data channel we created earlier
        let dc = pending
            .data_channel
            .ok_or_else(|| TransportError::ConnectionFailed("No data channel".to_string()))?;

        Ok(Arc::new(RealDataChannel { dc }))
    }
}
