//! Mock Nostr relay for signaling simulation
//!
//! Implements Nostr relay protocol:
//! - Client sends: EVENT, REQ, CLOSE
//! - Relay sends: EVENT, EOSE, OK, NOTICE
//!
//! Events are stored and sent to matching subscriptions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};

/// Event kinds
pub const KIND_PRESENCE: u32 = 30000;
pub const KIND_OFFER: u32 = 30001;
pub const KIND_ANSWER: u32 = 30002;
pub const KIND_CANDIDATE: u32 = 30003;

/// Nostr Event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Event {
    pub fn new(pubkey: impl Into<String>, kind: u32, content: impl Into<String>) -> Self {
        Self {
            id: format!("{:064x}", rand::random::<u128>()),
            pubkey: pubkey.into(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            kind,
            tags: Vec::new(),
            content: content.into(),
            sig: None,
        }
    }

    pub fn with_tag(mut self, tag: Vec<String>) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn with_p_tag(self, pubkey: impl Into<String>) -> Self {
        self.with_tag(vec!["p".to_string(), pubkey.into()])
    }

    pub fn get_tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == name)
            .map(|t| t[1].as_str())
    }

    pub fn get_p_tag(&self) -> Option<&str> {
        self.get_tag("p")
    }
}

/// Subscription filter
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u32>>,
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ids(mut self, ids: Vec<String>) -> Self {
        self.ids = Some(ids);
        self
    }

    pub fn authors(mut self, authors: Vec<String>) -> Self {
        self.authors = Some(authors);
        self
    }

    pub fn kinds(mut self, kinds: Vec<u32>) -> Self {
        self.kinds = Some(kinds);
        self
    }

    pub fn p_tags(mut self, tags: Vec<String>) -> Self {
        self.p_tags = Some(tags);
        self
    }

    pub fn since(mut self, timestamp: u64) -> Self {
        self.since = Some(timestamp);
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ref ids) = self.ids {
            if !ids.contains(&event.id) {
                return false;
            }
        }
        if let Some(ref authors) = self.authors {
            if !authors.contains(&event.pubkey) {
                return false;
            }
        }
        if let Some(ref kinds) = self.kinds {
            if !kinds.contains(&event.kind) {
                return false;
            }
        }
        if let Some(ref p_tags) = self.p_tags {
            let has_match = event.tags.iter().any(|t| {
                t.len() >= 2 && t[0] == "p" && p_tags.contains(&t[1])
            });
            if !has_match {
                return false;
            }
        }
        if let Some(since) = self.since {
            if event.created_at < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if event.created_at > until {
                return false;
            }
        }
        true
    }
}

/// Client -> Relay message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ClientMessage {
    Event { event: Event },
    Req { sub_id: String, filters: Vec<Filter> },
    Close { sub_id: String },
}

/// Relay -> Client message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum RelayMessage {
    Event { sub_id: String, event: Event },
    Eose { sub_id: String },
    Ok { event_id: String, success: bool, message: String },
    Notice { message: String },
}

/// A client connection to the relay
pub struct RelayClient {
    /// Client's pubkey (for identification)
    pub pubkey: String,
    /// Receive messages from relay
    rx: mpsc::Receiver<RelayMessage>,
    /// Send messages to relay
    tx: mpsc::Sender<ClientMessage>,
}

impl RelayClient {
    /// Publish an event
    pub async fn publish(&self, event: Event) -> Result<(), RelayError> {
        self.tx
            .send(ClientMessage::Event { event })
            .await
            .map_err(|_| RelayError::Disconnected)
    }

    /// Subscribe with filters, returns subscription ID
    pub async fn subscribe(&self, sub_id: impl Into<String>, filters: Vec<Filter>) -> Result<(), RelayError> {
        self.tx
            .send(ClientMessage::Req {
                sub_id: sub_id.into(),
                filters,
            })
            .await
            .map_err(|_| RelayError::Disconnected)
    }

    /// Unsubscribe
    pub async fn unsubscribe(&self, sub_id: impl Into<String>) -> Result<(), RelayError> {
        self.tx
            .send(ClientMessage::Close {
                sub_id: sub_id.into(),
            })
            .await
            .map_err(|_| RelayError::Disconnected)
    }

    /// Receive next message from relay
    pub async fn recv(&mut self) -> Option<RelayMessage> {
        self.rx.recv().await
    }

    /// Try to receive without blocking
    pub fn try_recv(&mut self) -> Option<RelayMessage> {
        self.rx.try_recv().ok()
    }
}

#[derive(Debug, Clone)]
pub enum RelayError {
    Disconnected,
}

/// Subscription state
struct Subscription {
    filters: Vec<Filter>,
    client_tx: mpsc::Sender<RelayMessage>,
}

/// Mock Nostr relay
pub struct MockRelay {
    /// Stored events
    events: RwLock<Vec<Event>>,
    /// Active subscriptions: client_id -> sub_id -> Subscription
    subscriptions: RwLock<HashMap<String, HashMap<String, Subscription>>>,
    /// Broadcast for new events (all connected clients listen)
    broadcast: broadcast::Sender<Event>,
    /// Next client ID
    next_client_id: AtomicU64,
}

impl MockRelay {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(10000);
        Arc::new(Self {
            events: RwLock::new(Vec::new()),
            subscriptions: RwLock::new(HashMap::new()),
            broadcast: tx,
            next_client_id: AtomicU64::new(1),
        })
    }

    /// Connect a client, returns client handle
    pub async fn connect(self: &Arc<Self>, pubkey: impl Into<String>) -> RelayClient {
        let pubkey = pubkey.into();
        let client_id = self.next_client_id.fetch_add(1, Ordering::Relaxed).to_string();

        let (to_client_tx, to_client_rx) = mpsc::channel(1000);
        let (from_client_tx, mut from_client_rx) = mpsc::channel::<ClientMessage>(1000);

        // Initialize empty subscription map for this client
        self.subscriptions
            .write()
            .await
            .insert(client_id.clone(), HashMap::new());

        // Spawn client message handler
        let relay = self.clone();
        let client_id_clone = client_id.clone();
        let to_client_tx_clone = to_client_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = from_client_rx.recv().await {
                relay
                    .handle_client_message(&client_id_clone, msg, &to_client_tx_clone)
                    .await;
            }
            // Client disconnected, cleanup subscriptions
            relay.subscriptions.write().await.remove(&client_id_clone);
        });

        // Spawn broadcast listener for this client
        let relay = self.clone();
        let client_id_clone = client_id.clone();
        let mut broadcast_rx = self.broadcast.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = broadcast_rx.recv().await {
                relay.send_to_matching_subs(&client_id_clone, &event).await;
            }
        });

        RelayClient {
            pubkey,
            rx: to_client_rx,
            tx: from_client_tx,
        }
    }

    async fn handle_client_message(
        &self,
        client_id: &str,
        msg: ClientMessage,
        client_tx: &mpsc::Sender<RelayMessage>,
    ) {
        match msg {
            ClientMessage::Event { event } => {
                // Store event
                self.events.write().await.push(event.clone());

                // Send OK
                let _ = client_tx
                    .send(RelayMessage::Ok {
                        event_id: event.id.clone(),
                        success: true,
                        message: String::new(),
                    })
                    .await;

                // Broadcast to all subscribers
                let _ = self.broadcast.send(event);
            }
            ClientMessage::Req { sub_id, filters } => {
                // Store subscription
                {
                    let mut subs = self.subscriptions.write().await;
                    if let Some(client_subs) = subs.get_mut(client_id) {
                        client_subs.insert(
                            sub_id.clone(),
                            Subscription {
                                filters: filters.clone(),
                                client_tx: client_tx.clone(),
                            },
                        );
                    }
                }

                // Send matching stored events
                let events = self.events.read().await;
                for event in events.iter() {
                    if filters.iter().any(|f| f.matches(event)) {
                        let _ = client_tx
                            .send(RelayMessage::Event {
                                sub_id: sub_id.clone(),
                                event: event.clone(),
                            })
                            .await;
                    }
                }

                // Send EOSE
                let _ = client_tx
                    .send(RelayMessage::Eose {
                        sub_id: sub_id.clone(),
                    })
                    .await;
            }
            ClientMessage::Close { sub_id } => {
                let mut subs = self.subscriptions.write().await;
                if let Some(client_subs) = subs.get_mut(client_id) {
                    client_subs.remove(&sub_id);
                }
            }
        }
    }

    async fn send_to_matching_subs(&self, client_id: &str, event: &Event) {
        let subs = self.subscriptions.read().await;
        if let Some(client_subs) = subs.get(client_id) {
            for (sub_id, sub) in client_subs {
                if sub.filters.iter().any(|f| f.matches(event)) {
                    let _ = sub
                        .client_tx
                        .send(RelayMessage::Event {
                            sub_id: sub_id.clone(),
                            event: event.clone(),
                        })
                        .await;
                }
            }
        }
    }

    /// Get event count (for testing)
    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Clear all events (for testing)
    pub async fn clear(&self) {
        self.events.write().await.clear();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_and_query() {
        let relay = MockRelay::new();
        let mut client = relay.connect("alice").await;

        // Publish event
        let event = Event::new("alice", KIND_PRESENCE, "hello");
        client.publish(event).await.unwrap();

        // Should get OK
        let msg = client.recv().await.unwrap();
        assert!(matches!(msg, RelayMessage::Ok { success: true, .. }));

        assert_eq!(relay.event_count().await, 1);
    }

    #[tokio::test]
    async fn test_subscribe_gets_past_events() {
        let relay = MockRelay::new();
        let mut client1 = relay.connect("alice").await;

        // Publish some events first
        client1.publish(Event::new("alice", KIND_PRESENCE, "1")).await.unwrap();
        client1.recv().await; // OK

        client1.publish(Event::new("alice", KIND_PRESENCE, "2")).await.unwrap();
        client1.recv().await; // OK

        // New client subscribes
        let mut client2 = relay.connect("bob").await;
        let filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        client2.subscribe("sub1", vec![filter]).await.unwrap();

        // Should receive past events
        let mut count = 0;
        loop {
            match client2.recv().await.unwrap() {
                RelayMessage::Event { .. } => count += 1,
                RelayMessage::Eose { .. } => break,
                _ => {}
            }
        }
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_subscribe_gets_new_events() {
        let relay = MockRelay::new();
        let mut client1 = relay.connect("alice").await;
        let mut client2 = relay.connect("bob").await;

        // Bob subscribes to alice's events
        let filter = Filter::new().authors(vec!["alice".into()]);
        client2.subscribe("sub1", vec![filter]).await.unwrap();

        // Wait for EOSE (no past events)
        loop {
            if matches!(client2.recv().await.unwrap(), RelayMessage::Eose { .. }) {
                break;
            }
        }

        // Alice publishes
        client1.publish(Event::new("alice", KIND_PRESENCE, "new")).await.unwrap();
        client1.recv().await; // OK

        // Bob should receive it
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = client2.try_recv();
        assert!(matches!(msg, Some(RelayMessage::Event { .. })));
    }

    #[tokio::test]
    async fn test_p_tag_filter() {
        let relay = MockRelay::new();
        let mut alice = relay.connect("alice").await;
        let mut bob = relay.connect("bob").await;

        // Bob subscribes to events tagged with his pubkey
        let filter = Filter::new().p_tags(vec!["bob".into()]);
        bob.subscribe("offers", vec![filter]).await.unwrap();
        loop {
            if matches!(bob.recv().await.unwrap(), RelayMessage::Eose { .. }) {
                break;
            }
        }

        // Alice sends offer to bob
        let offer = Event::new("alice", KIND_OFFER, "sdp...").with_p_tag("bob");
        alice.publish(offer).await.unwrap();
        alice.recv().await; // OK

        // Bob should receive it
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = bob.try_recv();
        assert!(matches!(msg, Some(RelayMessage::Event { .. })));
    }

    #[tokio::test]
    async fn test_unsubscribe() {
        let relay = MockRelay::new();
        let mut client = relay.connect("alice").await;

        // Subscribe
        let filter = Filter::new().kinds(vec![KIND_PRESENCE]);
        client.subscribe("sub1", vec![filter]).await.unwrap();
        loop {
            if matches!(client.recv().await.unwrap(), RelayMessage::Eose { .. }) {
                break;
            }
        }

        // Unsubscribe
        client.unsubscribe("sub1").await.unwrap();

        // Publish event - should NOT receive it
        client.publish(Event::new("alice", KIND_PRESENCE, "test")).await.unwrap();
        client.recv().await; // OK

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let msg = client.try_recv();
        // Should be None or not an Event for sub1
        assert!(msg.is_none() || !matches!(msg, Some(RelayMessage::Event { sub_id, .. }) if sub_id == "sub1"));
    }
}
