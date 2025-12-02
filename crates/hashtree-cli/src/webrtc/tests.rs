//! WebRTC module tests

use super::types::*;

#[test]
fn test_peer_id_display() {
    let peer_id = PeerId::new("abc123def456".to_string(), Some("uuid-12345".to_string()));
    assert_eq!(peer_id.to_string(), "abc123def456:uuid-12345");
}

#[test]
fn test_peer_id_short() {
    let peer_id = PeerId::new("abc123def456ghijklmnop".to_string(), Some("uuid-12345678".to_string()));
    assert_eq!(peer_id.short(), "abc123de:uuid-1");
}

#[test]
fn test_peer_id_from_string() {
    let peer_id = PeerId::from_string("abc123:uuid456").unwrap();
    assert_eq!(peer_id.pubkey, "abc123");
    assert_eq!(peer_id.uuid, "uuid456");
}

#[test]
fn test_peer_id_from_string_invalid() {
    assert!(PeerId::from_string("no-colon").is_none());
    assert!(PeerId::from_string("a:b:c").is_none());
}

#[test]
fn test_signaling_message_hello() {
    let msg = SignalingMessage::hello("my-uuid");
    assert_eq!(msg.msg_type(), "hello");
    assert_eq!(msg.peer_id(), "my-uuid");
    assert!(msg.recipient().is_none());
}

#[test]
fn test_signaling_message_offer() {
    let offer = serde_json::json!({"sdp": "test"});
    let msg = SignalingMessage::offer(offer.clone(), "recipient", "peer-id");
    assert_eq!(msg.msg_type(), "offer");
    assert_eq!(msg.recipient(), Some("recipient"));
    assert_eq!(msg.peer_id(), "peer-id");
}

#[test]
fn test_webrtc_config_default() {
    let config = WebRTCConfig::default();
    assert!(!config.relays.is_empty());
    assert!(config.max_outbound > 0);
    assert!(config.max_inbound > 0);
    assert!(!config.stun_servers.is_empty());
}

#[test]
fn test_generate_uuid() {
    let uuid1 = generate_uuid();
    let uuid2 = generate_uuid();

    // Should be 30 characters (15 + 15)
    assert_eq!(uuid1.len(), 30);
    assert_eq!(uuid2.len(), 30);

    // Should be different
    assert_ne!(uuid1, uuid2);
}

#[test]
fn test_peer_direction_display() {
    assert_eq!(PeerDirection::Inbound.to_string(), "inbound");
    assert_eq!(PeerDirection::Outbound.to_string(), "outbound");
}
