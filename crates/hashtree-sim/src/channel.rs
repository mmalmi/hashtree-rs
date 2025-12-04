//! Peer communication channels
//!
//! Trait for sending/receiving bytes to/from peers.
//! Different implementations can add latency, packet loss, etc.

use crate::NodeId;
use async_trait::async_trait;
use std::time::Duration;

/// A channel to a single peer for sending/receiving bytes
#[async_trait]
pub trait PeerChannel: Send + Sync {
    /// Remote peer ID
    fn peer_id(&self) -> NodeId;

    /// Send bytes to peer
    async fn send(&self, data: Vec<u8>) -> Result<(), ChannelError>;

    /// Receive bytes from peer (with timeout)
    async fn recv(&self, timeout: Duration) -> Result<Vec<u8>, ChannelError>;

    /// Check if channel is still connected
    fn is_connected(&self) -> bool;

    /// Bytes sent through this channel
    fn bytes_sent(&self) -> u64;

    /// Bytes received through this channel
    fn bytes_received(&self) -> u64;
}

#[derive(Debug, Clone)]
pub enum ChannelError {
    Disconnected,
    Timeout,
    SendFailed(String),
}

/// Mock channel for testing - instant delivery via mpsc
pub struct MockChannel {
    peer_id: NodeId,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    bytes_sent: std::sync::atomic::AtomicU64,
    bytes_received: std::sync::atomic::AtomicU64,
}

impl MockChannel {
    /// Create a pair of connected mock channels
    pub fn pair(id_a: NodeId, id_b: NodeId) -> (Self, Self) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(100);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(100);

        let chan_a = MockChannel {
            peer_id: id_b,
            tx: tx_b,
            rx: tokio::sync::Mutex::new(rx_a),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        };

        let chan_b = MockChannel {
            peer_id: id_a,
            tx: tx_a,
            rx: tokio::sync::Mutex::new(rx_b),
            bytes_sent: std::sync::atomic::AtomicU64::new(0),
            bytes_received: std::sync::atomic::AtomicU64::new(0),
        };

        (chan_a, chan_b)
    }
}

#[async_trait]
impl PeerChannel for MockChannel {
    fn peer_id(&self) -> NodeId {
        self.peer_id
    }

    async fn send(&self, data: Vec<u8>) -> Result<(), ChannelError> {
        let len = data.len() as u64;
        self.tx
            .send(data)
            .await
            .map_err(|_| ChannelError::Disconnected)?;
        self.bytes_sent
            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn recv(&self, timeout: Duration) -> Result<Vec<u8>, ChannelError> {
        let mut rx = self.rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(data)) => {
                self.bytes_received
                    .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                Ok(data)
            }
            Ok(None) => Err(ChannelError::Disconnected),
            Err(_) => Err(ChannelError::Timeout),
        }
    }

    fn is_connected(&self) -> bool {
        !self.tx.is_closed()
    }

    fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn bytes_received(&self) -> u64 {
        self.bytes_received
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Channel wrapper that adds latency
pub struct LatencyChannel<C: PeerChannel> {
    inner: C,
    latency: Duration,
}

impl<C: PeerChannel> LatencyChannel<C> {
    pub fn new(inner: C, latency: Duration) -> Self {
        Self { inner, latency }
    }
}

#[async_trait]
impl<C: PeerChannel> PeerChannel for LatencyChannel<C> {
    fn peer_id(&self) -> NodeId {
        self.inner.peer_id()
    }

    async fn send(&self, data: Vec<u8>) -> Result<(), ChannelError> {
        tokio::time::sleep(self.latency).await;
        self.inner.send(data).await
    }

    async fn recv(&self, timeout: Duration) -> Result<Vec<u8>, ChannelError> {
        // Account for latency in timeout
        let adjusted = timeout.saturating_sub(self.latency);
        if adjusted.is_zero() {
            return Err(ChannelError::Timeout);
        }
        self.inner.recv(adjusted).await
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    fn bytes_sent(&self) -> u64 {
        self.inner.bytes_sent()
    }

    fn bytes_received(&self) -> u64 {
        self.inner.bytes_received()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_channel_roundtrip() {
        let (chan_a, chan_b) = MockChannel::pair(1, 2);

        // A sends to B
        chan_a.send(b"hello".to_vec()).await.unwrap();
        let received = chan_b.recv(Duration::from_secs(1)).await.unwrap();
        assert_eq!(received, b"hello");

        // B sends to A
        chan_b.send(b"world".to_vec()).await.unwrap();
        let received = chan_a.recv(Duration::from_secs(1)).await.unwrap();
        assert_eq!(received, b"world");

        // Check byte counts
        assert_eq!(chan_a.bytes_sent(), 5);
        assert_eq!(chan_a.bytes_received(), 5);
    }

    #[tokio::test]
    async fn test_mock_channel_timeout() {
        let (chan_a, _chan_b) = MockChannel::pair(1, 2);

        // Should timeout since nothing sent
        let result = chan_a.recv(Duration::from_millis(10)).await;
        assert!(matches!(result, Err(ChannelError::Timeout)));
    }
}
