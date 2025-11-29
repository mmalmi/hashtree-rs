//! Tests for WebRTC types

use hashtree_webrtc::{
    DataMessage, PeerId, PeerState, SignalingMessage, WebRTCStats, WebRTCStoreConfig,
};

#[test]
fn test_peer_id_creation() {
    let peer_id = PeerId::new("abc123".to_string(), "uuid-456".to_string());
    assert_eq!(peer_id.pubkey, "abc123");
    assert_eq!(peer_id.uuid, "uuid-456");
}

#[test]
fn test_peer_id_to_string() {
    let peer_id = PeerId::new("abc123".to_string(), "uuid-456".to_string());
    assert_eq!(peer_id.to_peer_string(), "abc123:uuid-456");
}

#[test]
fn test_peer_id_from_string() {
    let peer_id = PeerId::from_peer_string("abc123:uuid-456").unwrap();
    assert_eq!(peer_id.pubkey, "abc123");
    assert_eq!(peer_id.uuid, "uuid-456");
}

#[test]
fn test_peer_id_from_string_invalid() {
    assert!(PeerId::from_peer_string("invalid").is_none());
    assert!(PeerId::from_peer_string("").is_none());
}

#[test]
fn test_signaling_message_hello_serialize() {
    let msg = SignalingMessage::Hello {
        peer_id: "test:123".to_string(),
        roots: vec!["abc".to_string(), "def".to_string()],
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"hello\""));
    assert!(json.contains("\"peerId\":\"test:123\""));
}

#[test]
fn test_signaling_message_offer_serialize() {
    let msg = SignalingMessage::Offer {
        peer_id: "peer1".to_string(),
        target_peer_id: "peer2".to_string(),
        sdp: "v=0\r\n...".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"offer\""));
    assert!(json.contains("\"targetPeerId\":\"peer2\""));
}

#[test]
fn test_signaling_message_roundtrip() {
    let original = SignalingMessage::Answer {
        peer_id: "peer1".to_string(),
        target_peer_id: "peer2".to_string(),
        sdp: "v=0\r\ntest sdp".to_string(),
    };
    let json = serde_json::to_string(&original).unwrap();
    let parsed: SignalingMessage = serde_json::from_str(&json).unwrap();

    match parsed {
        SignalingMessage::Answer { peer_id, target_peer_id, sdp } => {
            assert_eq!(peer_id, "peer1");
            assert_eq!(target_peer_id, "peer2");
            assert_eq!(sdp, "v=0\r\ntest sdp");
        }
        _ => panic!("Wrong message type"),
    }
}

#[test]
fn test_data_message_request_serialize() {
    let msg = DataMessage::Request {
        id: 42,
        hash: "abcd1234".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"req\""));
    assert!(json.contains("\"id\":42"));
    assert!(json.contains("\"hash\":\"abcd1234\""));
}

#[test]
fn test_data_message_response_serialize() {
    let msg = DataMessage::Response {
        id: 42,
        hash: "abcd1234".to_string(),
        found: true,
        size: Some(1024),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"res\""));
    assert!(json.contains("\"found\":true"));
    assert!(json.contains("\"size\":1024"));
}

#[test]
fn test_data_message_response_not_found() {
    let msg = DataMessage::Response {
        id: 42,
        hash: "abcd1234".to_string(),
        found: false,
        size: None,
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"found\":false"));
    assert!(!json.contains("\"size\":")); // size should be omitted when None
}

#[test]
fn test_data_message_have() {
    let msg = DataMessage::Have {
        hashes: vec!["hash1".to_string(), "hash2".to_string()],
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"have\""));
    assert!(json.contains("\"hashes\":[\"hash1\",\"hash2\"]"));
}

#[test]
fn test_data_message_root_update() {
    let msg = DataMessage::RootUpdate {
        hash: "newhash".to_string(),
        size: Some(2048),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("\"type\":\"root\""));
}

#[test]
fn test_webrtc_store_config_default() {
    let config = WebRTCStoreConfig::default();
    assert_eq!(config.satisfied_connections, 3);
    assert_eq!(config.max_connections, 10);
    assert_eq!(config.request_timeout_ms, 10000);
    assert!(!config.debug);
}

#[test]
fn test_peer_state_equality() {
    assert_eq!(PeerState::New, PeerState::New);
    assert_eq!(PeerState::Connected, PeerState::Connected);
    assert_ne!(PeerState::New, PeerState::Connected);
}

#[test]
fn test_webrtc_stats_default() {
    let stats = WebRTCStats::default();
    assert_eq!(stats.connected_peers, 0);
    assert_eq!(stats.pending_requests, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}
