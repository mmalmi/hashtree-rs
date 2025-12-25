//! Nostr relay transport implementation
//!
//! Wraps nostr-sdk Client to implement the RelayTransport trait for production use.

use async_trait::async_trait;
use nostr_sdk::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{broadcast, Mutex};

use crate::transport::{RelayTransport, TransportError};
use crate::types::{SignalingMessage, NOSTR_KIND_HASHTREE};

/// Nostr relay transport for production WebRTC signaling
pub struct NostrRelayTransport {
    /// Our peer ID (pubkey:uuid)
    peer_id: String,
    /// Our pubkey (hex)
    pubkey: String,
    /// Nostr client
    client: Client,
    /// Message buffer for received signaling messages
    buffer: Mutex<Vec<SignalingMessage>>,
    /// Whether we're connected
    connected: AtomicBool,
    /// Receiver for messages from event handler
    msg_rx: Mutex<Option<broadcast::Receiver<SignalingMessage>>>,
    /// Sender for forwarding messages from event handler
    msg_tx: broadcast::Sender<SignalingMessage>,
    /// Debug flag
    debug: bool,
}

impl NostrRelayTransport {
    /// Create a new Nostr relay transport
    pub fn new(keys: Keys, peer_uuid: String, debug: bool) -> Self {
        let pubkey = keys.public_key().to_hex();
        let peer_id = format!("{}:{}", pubkey, peer_uuid);

        // Create client with in-memory database to avoid event deduplication
        let client = ClientBuilder::new()
            .signer(keys)
            .database(nostr_sdk::database::MemoryDatabase::new())
            .build();

        let (msg_tx, msg_rx) = broadcast::channel(1000);

        Self {
            peer_id,
            pubkey,
            client,
            buffer: Mutex::new(Vec::new()),
            connected: AtomicBool::new(false),
            msg_rx: Mutex::new(Some(msg_rx)),
            msg_tx,
            debug,
        }
    }

    /// Start the background event handler
    fn start_event_handler(&self) {
        let msg_tx = self.msg_tx.clone();
        let peer_id = self.peer_id.clone();
        let debug = self.debug;

        // Get notifications receiver
        let mut notifications = self.client.notifications();

        tokio::spawn(async move {
            loop {
                match notifications.recv().await {
                    Ok(notification) => {
                        if let RelayPoolNotification::Event { event, .. } = notification {
                            if event.kind == Kind::Custom(NOSTR_KIND_HASHTREE) {
                                if let Ok(msg) =
                                    serde_json::from_str::<SignalingMessage>(&event.content)
                                {
                                    // Only forward messages for us or broadcasts
                                    if msg.is_for(&peer_id) || msg.target_peer_id().is_none() {
                                        if debug {
                                            let preview = if event.content.len() > 60 {
                                                format!("{}...", &event.content[..60])
                                            } else {
                                                event.content.clone()
                                            };
                                            println!("[NostrTransport] Received: {}", preview);
                                        }
                                        let _ = msg_tx.send(msg);
                                    }
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });
    }

    /// Get the nostr client (for advanced usage)
    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[async_trait]
impl RelayTransport for NostrRelayTransport {
    async fn connect(&self, relays: &[String]) -> Result<(), TransportError> {
        // Add relays
        for relay in relays {
            self.client
                .add_relay(relay)
                .await
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        }

        // Connect
        self.client.connect().await;

        // Subscribe to hashtree signaling events
        let filter = Filter::new()
            .kind(Kind::Custom(NOSTR_KIND_HASHTREE))
            .since(Timestamp::now());

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Start event handler
        self.start_event_handler();

        self.connected.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn disconnect(&self) {
        self.connected.store(false, Ordering::Relaxed);
        let _ = self.client.disconnect().await;
    }

    async fn publish(&self, msg: SignalingMessage) -> Result<(), TransportError> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(TransportError::NotConnected);
        }

        let json = serde_json::to_string(&msg)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        if self.debug {
            println!(
                "[NostrTransport] Publishing: {}",
                &json[..json.len().min(80)]
            );
        }

        let builder = EventBuilder::new(Kind::Custom(NOSTR_KIND_HASHTREE), json, []);

        match self.client.send_event_builder(builder).await {
            Ok(output) => {
                if output.success.is_empty() {
                    return Err(TransportError::SendFailed("No relay accepted event".to_string()));
                }
                Ok(())
            }
            Err(e) => Err(TransportError::SendFailed(e.to_string())),
        }
    }

    async fn recv(&self) -> Option<SignalingMessage> {
        // Check buffer first
        {
            let mut buffer = self.buffer.lock().await;
            if !buffer.is_empty() {
                return Some(buffer.remove(0));
            }
        }

        // Take the receiver if we have it
        let rx = self.msg_rx.lock().await.take();
        if let Some(mut rx) = rx {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        // Put receiver back for next call
                        *self.msg_rx.lock().await = Some(rx);
                        return Some(msg);
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        }
        None
    }

    fn try_recv(&self) -> Option<SignalingMessage> {
        // Check buffer first
        if let Ok(mut buffer) = self.buffer.try_lock() {
            if !buffer.is_empty() {
                return Some(buffer.remove(0));
            }
        }

        // Try non-blocking receive
        if let Ok(mut rx_guard) = self.msg_rx.try_lock() {
            if let Some(ref mut rx) = *rx_guard {
                match rx.try_recv() {
                    Ok(msg) => return Some(msg),
                    Err(_) => return None,
                }
            }
        }
        None
    }

    fn peer_id(&self) -> &str {
        &self.peer_id
    }

    fn pubkey(&self) -> &str {
        &self.pubkey
    }
}
