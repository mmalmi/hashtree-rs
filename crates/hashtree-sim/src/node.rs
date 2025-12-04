//! Simulated P2P node
//!
//! A node that:
//! 1. Announces presence on relay
//! 2. Discovers other nodes
//! 3. Establishes peer connections via signaling
//! 4. Uses NetworkStore for data fetching

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::channel::{MockChannel, PeerChannel};
use crate::relay::{
    Event, Filter, MockRelay, RelayClient, RelayMessage, KIND_ANSWER, KIND_OFFER, KIND_PRESENCE,
};
use crate::store::SimStore;

/// Signaling content types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum SignalingContent {
    Presence { node_id: String },
    Offer { sdp: String },
    Answer { sdp: String },
}

/// Configuration for a sim node
#[derive(Clone)]
pub struct NodeConfig {
    /// Max peers to connect to
    pub max_peers: usize,
    /// Connection timeout (ms)
    pub connect_timeout_ms: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            max_peers: 5,
            connect_timeout_ms: 5000,
        }
    }
}

/// A simulated peer connection
pub struct SimPeer {
    pub remote_id: String,
    pub channel: Arc<dyn PeerChannel>,
    pub connected_at: std::time::Instant,
}

/// Pending outbound connection (we sent offer, waiting for answer)
struct PendingConnection {
    our_channel: Arc<MockChannel>,
}

/// Simulated P2P node
pub struct SimNode {
    /// Node identifier (public key)
    pub id: String,
    /// Local storage
    pub store: Arc<SimStore>,
    /// Connected peers
    peers: RwLock<HashMap<String, SimPeer>>,
    /// Pending outbound connections (we sent offer)
    pending_outbound: RwLock<HashMap<String, PendingConnection>>,
    /// Configuration
    config: NodeConfig,
}

impl SimNode {
    pub fn new(id: impl Into<String>, config: NodeConfig) -> Arc<Self> {
        let id = id.into();
        Arc::new(Self {
            store: Arc::new(SimStore::new(id.parse().unwrap_or(0))),
            id,
            peers: RwLock::new(HashMap::new()),
            pending_outbound: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Connect to relay and announce presence
    pub async fn connect_to_relay(self: &Arc<Self>, relay: &Arc<MockRelay>) -> RelayClient {
        let mut client = relay.connect(self.id.clone()).await;

        // Announce presence
        let presence = Event::new(
            self.id.clone(),
            KIND_PRESENCE,
            serde_json::to_string(&SignalingContent::Presence {
                node_id: self.id.clone(),
            })
            .unwrap(),
        );
        let _ = client.publish(presence).await;

        // Consume the OK response
        while let Some(msg) = client.recv().await {
            if matches!(msg, RelayMessage::Ok { .. }) {
                break;
            }
        }

        client
    }

    /// Subscribe to offers and answers directed at us
    pub async fn setup_signaling(
        &self,
        client: &RelayClient,
    ) -> Result<(), crate::relay::RelayError> {
        // Subscribe to offers for us
        let offer_filter = Filter::new()
            .kinds(vec![KIND_OFFER])
            .p_tags(vec![self.id.clone()]);
        client.subscribe("offers", vec![offer_filter]).await?;

        // Subscribe to answers for us
        let answer_filter = Filter::new()
            .kinds(vec![KIND_ANSWER])
            .p_tags(vec![self.id.clone()]);
        client.subscribe("answers", vec![answer_filter]).await?;

        Ok(())
    }

    /// Discover peers by querying presence events
    pub async fn discover_peers(&self, client: &RelayClient) -> Result<(), crate::relay::RelayError> {
        let filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        client.subscribe("discovery", vec![filter]).await
    }

    /// Send WebRTC offer to a peer
    pub async fn send_offer(
        self: &Arc<Self>,
        client: &RelayClient,
        target: &str,
    ) -> Result<(), crate::relay::RelayError> {
        // Check if already connected or pending
        if self.peers.read().await.contains_key(target) {
            return Ok(());
        }
        if self.pending_outbound.read().await.contains_key(target) {
            return Ok(());
        }
        if self.peers.read().await.len() >= self.config.max_peers {
            return Ok(());
        }

        // Create our end of the channel (we'll get their end when they answer)
        let (our_chan, their_chan) = MockChannel::pair(
            self.id.parse().unwrap_or(0),
            target.parse().unwrap_or(0),
        );

        // Store pending connection with channel reference for answer handling
        // We encode a channel ID in the offer so the answerer can reference it
        let channel_id = format!("{}_{}", self.id, target);

        self.pending_outbound.write().await.insert(
            target.to_string(),
            PendingConnection {
                our_channel: Arc::new(our_chan),
            },
        );

        // Store their channel half in a global registry for the answerer to retrieve
        CHANNEL_REGISTRY.write().await.insert(channel_id.clone(), Arc::new(their_chan));

        let offer_content = SignalingContent::Offer {
            sdp: channel_id,
        };
        let offer = Event::new(
            self.id.clone(),
            KIND_OFFER,
            serde_json::to_string(&offer_content).unwrap(),
        )
        .with_p_tag(target);

        client.publish(offer).await
    }

    /// Handle incoming offer - create answer and establish connection
    pub async fn handle_offer(
        self: &Arc<Self>,
        client: &RelayClient,
        event: &Event,
    ) -> Result<(), crate::relay::RelayError> {
        let from = &event.pubkey;

        // Check if already connected
        if self.peers.read().await.contains_key(from) {
            return Ok(());
        }
        if self.peers.read().await.len() >= self.config.max_peers {
            return Ok(());
        }

        // Parse offer content to get channel ID
        let content: SignalingContent = match serde_json::from_str(&event.content) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let channel_id = match content {
            SignalingContent::Offer { sdp } => sdp,
            _ => return Ok(()),
        };

        // Get our channel half from the registry
        let their_channel = CHANNEL_REGISTRY.write().await.remove(&channel_id);
        let channel = match their_channel {
            Some(c) => c,
            None => return Ok(()), // Channel not found, maybe stale offer
        };

        // Store the connection
        {
            let mut peers = self.peers.write().await;
            peers.insert(
                from.clone(),
                SimPeer {
                    remote_id: from.clone(),
                    channel,
                    connected_at: std::time::Instant::now(),
                },
            );
        }

        // Send answer
        let answer_content = SignalingContent::Answer {
            sdp: channel_id,
        };
        let answer = Event::new(
            self.id.clone(),
            KIND_ANSWER,
            serde_json::to_string(&answer_content).unwrap(),
        )
        .with_p_tag(from);

        client.publish(answer).await
    }

    /// Handle incoming answer - complete the connection
    pub async fn handle_answer(&self, event: &Event) {
        let from = &event.pubkey;

        // Get pending connection
        let pending = self.pending_outbound.write().await.remove(from);
        let pending = match pending {
            Some(p) => p,
            None => return, // No pending connection
        };

        // Check if already connected (race condition)
        if self.peers.read().await.contains_key(from) {
            return;
        }

        // Complete the connection
        let mut peers = self.peers.write().await;
        peers.insert(
            from.clone(),
            SimPeer {
                remote_id: from.clone(),
                channel: pending.our_channel,
                connected_at: std::time::Instant::now(),
            },
        );
    }

    /// Process relay messages - call this in a loop
    pub async fn process_message(
        self: &Arc<Self>,
        client: &RelayClient,
        msg: RelayMessage,
    ) -> Option<String> {
        match msg {
            RelayMessage::Event { sub_id, event } => {
                match sub_id.as_str() {
                    "offers" => {
                        let _ = self.handle_offer(client, &event).await;
                    }
                    "answers" => {
                        self.handle_answer(&event).await;
                    }
                    "discovery" => {
                        // Found a peer's presence
                        if event.pubkey != self.id {
                            return Some(event.pubkey);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        None
    }

    /// Get connected peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get peer IDs
    pub async fn peer_ids(&self) -> Vec<String> {
        self.peers.read().await.keys().cloned().collect()
    }

    /// Get a peer's channel
    pub async fn get_peer_channel(&self, peer_id: &str) -> Option<Arc<dyn PeerChannel>> {
        self.peers.read().await.get(peer_id).map(|p| p.channel.clone())
    }
}

// Global channel registry for signaling
// Maps channel_id -> channel half waiting to be claimed
lazy_static::lazy_static! {
    static ref CHANNEL_REGISTRY: RwLock<HashMap<String, Arc<MockChannel>>> = RwLock::new(HashMap::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_node_announces_presence() {
        let relay = MockRelay::new();
        let node = SimNode::new("node1", NodeConfig::default());

        let _client = node.connect_to_relay(&relay).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(relay.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_two_nodes_connect() {
        let relay = MockRelay::new();

        // Node 1 connects first
        let node1 = SimNode::new("1", NodeConfig::default());
        let mut client1 = node1.connect_to_relay(&relay).await;
        node1.setup_signaling(&client1).await.unwrap();

        // Drain EOSE messages
        tokio::time::sleep(Duration::from_millis(10)).await;
        while client1.try_recv().is_some() {}

        // Node 2 connects
        let node2 = SimNode::new("2", NodeConfig::default());
        let mut client2 = node2.connect_to_relay(&relay).await;
        node2.setup_signaling(&client2).await.unwrap();

        // Drain EOSE messages
        tokio::time::sleep(Duration::from_millis(10)).await;
        while client2.try_recv().is_some() {}

        // Node 1 sends offer to node 2
        node1.send_offer(&client1, "2").await.unwrap();

        // Give time for message to propagate
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Node 2 should receive offer and send answer
        while let Some(msg) = client2.try_recv() {
            node2.process_message(&client2, msg).await;
        }

        // Node 1 should receive answer
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Some(msg) = client1.try_recv() {
            node1.process_message(&client1, msg).await;
        }

        // Both should be connected
        assert_eq!(node1.peer_count().await, 1);
        assert_eq!(node2.peer_count().await, 1);
        assert!(node1.peer_ids().await.contains(&"2".to_string()));
        assert!(node2.peer_ids().await.contains(&"1".to_string()));
    }

    #[tokio::test]
    async fn test_peer_discovery() {
        let relay = MockRelay::new();

        // Several nodes connect and announce presence
        let node1 = SimNode::new("1", NodeConfig::default());
        let _client1 = node1.connect_to_relay(&relay).await;

        let node2 = SimNode::new("2", NodeConfig::default());
        let _client2 = node2.connect_to_relay(&relay).await;

        let node3 = SimNode::new("3", NodeConfig::default());
        let _client3 = node3.connect_to_relay(&relay).await;

        // Give time for presence announcements
        tokio::time::sleep(Duration::from_millis(10)).await;

        // New node discovers existing peers
        let new_node = SimNode::new("new", NodeConfig::default());
        let mut new_client = new_node.connect_to_relay(&relay).await;

        // Subscribe to presence events
        new_node.discover_peers(&new_client).await.unwrap();

        // Collect discovered peers
        let mut discovered = Vec::new();
        tokio::time::sleep(Duration::from_millis(50)).await;

        while let Some(msg) = new_client.try_recv() {
            if let Some(peer_id) = new_node.process_message(&new_client, msg).await {
                discovered.push(peer_id);
            }
        }

        // Should have discovered the 3 existing nodes
        assert!(discovered.contains(&"1".to_string()));
        assert!(discovered.contains(&"2".to_string()));
        assert!(discovered.contains(&"3".to_string()));
    }
}
