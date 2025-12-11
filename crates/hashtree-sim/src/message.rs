//! Wire message format - MessagePack encoding matching TypeScript WebRTC protocol
//!
//! Wire format: [type byte][msgpack body]
//! Request:  [0x00][msgpack: {h: bytes32, htl?: u8}]
//! Response: [0x01][msgpack: {h: bytes32, d: bytes}]

use serde::{Deserialize, Serialize};

/// Content hash (SHA-256)
pub type Hash = [u8; 32];

/// Message type bytes (prefix before MessagePack body)
pub const MSG_TYPE_REQUEST: u8 = 0x00;
pub const MSG_TYPE_RESPONSE: u8 = 0x01;

/// HTL (Hops To Live) constants - Freenet-style probabilistic decrement
pub const MAX_HTL: u8 = 10;
pub const DECREMENT_AT_MAX_PROB: f64 = 0.5;  // 50% chance to decrement at max
pub const DECREMENT_AT_MIN_PROB: f64 = 0.25; // 25% chance to decrement at 1

/// Per-peer HTL config (Freenet-style probabilistic decrement)
/// Generated once per peer connection, stays fixed for connection lifetime
#[derive(Clone, Debug)]
pub struct PeerHTLConfig {
    pub decrement_at_max: bool,  // true = decrement at MAX_HTL
    pub decrement_at_min: bool,  // true = decrement at HTL=1
}

impl PeerHTLConfig {
    /// Generate random HTL config for a new peer connection
    pub fn random() -> Self {
        Self {
            decrement_at_max: rand::random::<f64>() < DECREMENT_AT_MAX_PROB,
            decrement_at_min: rand::random::<f64>() < DECREMENT_AT_MIN_PROB,
        }
    }

    /// Deterministic config for testing
    pub fn deterministic(decrement_at_max: bool, decrement_at_min: bool) -> Self {
        Self { decrement_at_max, decrement_at_min }
    }
}

/// Decrement HTL using peer's config (Freenet-style probabilistic)
/// Called when SENDING to a peer, not on receive
pub fn decrement_htl(htl: u8, config: &PeerHTLConfig) -> u8 {
    if htl == 0 {
        return 0;
    }

    if htl == MAX_HTL {
        // At max: only decrement if this peer's config says so
        if config.decrement_at_max { htl - 1 } else { htl }
    } else if htl == 1 {
        // At min: only decrement if this peer's config says so
        if config.decrement_at_min { 0 } else { htl }
    } else {
        // Middle values: always decrement
        htl - 1
    }
}

/// Check if a request should be forwarded based on HTL
pub fn should_forward(htl: u8) -> bool {
    htl > 0
}

/// Request body (MessagePack encoded)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRequest {
    /// 32-byte hash
    #[serde(with = "serde_bytes")]
    pub h: Vec<u8>,
    /// Hops To Live (optional, defaults to MAX_HTL if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub htl: Option<u8>,
}

impl DataRequest {
    pub fn new(hash: Hash, htl: u8) -> Self {
        Self {
            h: hash.to_vec(),
            htl: Some(htl),
        }
    }

    pub fn hash(&self) -> Option<Hash> {
        if self.h.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.h);
            Some(hash)
        } else {
            None
        }
    }

    pub fn htl_value(&self) -> u8 {
        self.htl.unwrap_or(MAX_HTL)
    }
}

/// Response body (MessagePack encoded)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataResponse {
    /// 32-byte hash
    #[serde(with = "serde_bytes")]
    pub h: Vec<u8>,
    /// Data
    #[serde(with = "serde_bytes")]
    pub d: Vec<u8>,
}

impl DataResponse {
    pub fn new(hash: Hash, data: Vec<u8>) -> Self {
        Self {
            h: hash.to_vec(),
            d: data,
        }
    }

    pub fn hash(&self) -> Option<Hash> {
        if self.h.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.h);
            Some(hash)
        } else {
            None
        }
    }
}

/// Parse result
#[derive(Debug, Clone)]
pub enum ParsedMessage {
    Request(DataRequest),
    Response(DataResponse),
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    UnknownType(u8),
    MsgpackError(String),
}

/// Encode a request message
/// Format: [type:1][msgpack body]
pub fn encode_request(hash: &Hash, htl: u8) -> Vec<u8> {
    let req = DataRequest::new(*hash, htl);
    let body = rmp_serde::to_vec(&req).expect("msgpack encode failed");
    let mut buf = Vec::with_capacity(1 + body.len());
    buf.push(MSG_TYPE_REQUEST);
    buf.extend_from_slice(&body);
    buf
}

/// Encode a response message
/// Format: [type:1][msgpack body]
pub fn encode_response(hash: &Hash, data: &[u8]) -> Vec<u8> {
    let res = DataResponse::new(*hash, data.to_vec());
    let body = rmp_serde::to_vec(&res).expect("msgpack encode failed");
    let mut buf = Vec::with_capacity(1 + body.len());
    buf.push(MSG_TYPE_RESPONSE);
    buf.extend_from_slice(&body);
    buf
}

/// Parse a message from bytes
pub fn parse(bytes: &[u8]) -> Result<ParsedMessage, ParseError> {
    if bytes.len() < 2 {
        return Err(ParseError::TooShort);
    }

    let msg_type = bytes[0];
    let body = &bytes[1..];

    match msg_type {
        MSG_TYPE_REQUEST => {
            let req: DataRequest = rmp_serde::from_slice(body)
                .map_err(|e| ParseError::MsgpackError(e.to_string()))?;
            Ok(ParsedMessage::Request(req))
        }
        MSG_TYPE_RESPONSE => {
            let res: DataResponse = rmp_serde::from_slice(body)
                .map_err(|e| ParseError::MsgpackError(e.to_string()))?;
            Ok(ParsedMessage::Response(res))
        }
        t => Err(ParseError::UnknownType(t)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let hash = [42u8; 32];
        let htl = 7;
        let bytes = encode_request(&hash, htl);

        // First byte should be request type
        assert_eq!(bytes[0], MSG_TYPE_REQUEST);

        match parse(&bytes).unwrap() {
            ParsedMessage::Request(req) => {
                assert_eq!(req.hash().unwrap(), hash);
                assert_eq!(req.htl_value(), htl);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let hash = [42u8; 32];
        let data = b"hello world";
        let bytes = encode_response(&hash, data);

        // First byte should be response type
        assert_eq!(bytes[0], MSG_TYPE_RESPONSE);

        match parse(&bytes).unwrap() {
            ParsedMessage::Response(res) => {
                assert_eq!(res.hash().unwrap(), hash);
                assert_eq!(res.d, data);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_htl_decrement() {
        // Config that always decrements
        let always_dec = PeerHTLConfig::deterministic(true, true);
        assert_eq!(decrement_htl(MAX_HTL, &always_dec), MAX_HTL - 1);
        assert_eq!(decrement_htl(5, &always_dec), 4);
        assert_eq!(decrement_htl(1, &always_dec), 0);
        assert_eq!(decrement_htl(0, &always_dec), 0);

        // Config that never decrements at extremes
        let never_extreme = PeerHTLConfig::deterministic(false, false);
        assert_eq!(decrement_htl(MAX_HTL, &never_extreme), MAX_HTL); // stays at max
        assert_eq!(decrement_htl(5, &never_extreme), 4); // middle always decrements
        assert_eq!(decrement_htl(1, &never_extreme), 1); // stays at 1
        assert_eq!(decrement_htl(0, &never_extreme), 0);
    }

    #[test]
    fn test_should_forward() {
        assert!(should_forward(10));
        assert!(should_forward(1));
        assert!(!should_forward(0));
    }

    #[test]
    fn test_parse_garbage() {
        // Empty
        assert!(matches!(parse(&[]), Err(ParseError::TooShort)));

        // Unknown type
        assert!(matches!(parse(&[0xFF, 0x00]), Err(ParseError::UnknownType(0xFF))));

        // Invalid msgpack
        assert!(matches!(parse(&[MSG_TYPE_REQUEST, 0xFF, 0xFF]), Err(ParseError::MsgpackError(_))));
    }

    #[test]
    fn test_default_htl() {
        // Request without explicit HTL should default to MAX_HTL
        let req = DataRequest {
            h: vec![0u8; 32],
            htl: None,
        };
        assert_eq!(req.htl_value(), MAX_HTL);
    }
}
