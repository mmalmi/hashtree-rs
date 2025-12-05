//! Wire message format
//!
//! Messages are raw bytes. Recipient parses and validates.
//! Malicious nodes can send garbage.

/// Content hash (SHA-256)
pub type Hash = [u8; 32];

/// Request identifier
pub type RequestId = u32;

/// Message types (first byte)
pub const MSG_REQUEST: u8 = 0x01;
pub const MSG_RESPONSE: u8 = 0x02;
pub const MSG_PUSH: u8 = 0x04;

/// Parse result
#[derive(Debug, Clone)]
pub enum ParsedMessage {
    Request { id: RequestId, hash: Hash },
    Response { id: RequestId, hash: Hash, data: Vec<u8> },
    Push { hash: Hash, data: Vec<u8> },
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    UnknownType(u8),
    InvalidLength,
}

/// Encode a request message
/// Format: [type:1][id:4][hash:32] = 37 bytes
pub fn encode_request(id: RequestId, hash: &Hash) -> Vec<u8> {
    let mut buf = Vec::with_capacity(37);
    buf.push(MSG_REQUEST);
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(hash);
    buf
}

/// Encode a response message (with data)
/// Format: [type:1][id:4][hash:32][data:...] = 37 + data_len
pub fn encode_response(id: RequestId, hash: &Hash, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(37 + data.len());
    buf.push(MSG_RESPONSE);
    buf.extend_from_slice(&id.to_le_bytes());
    buf.extend_from_slice(hash);
    buf.extend_from_slice(data);
    buf
}

/// Encode a push message (unsolicited data)
/// Format: [type:1][hash:32][data:...] = 33 + data_len
pub fn encode_push(hash: &Hash, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(33 + data.len());
    buf.push(MSG_PUSH);
    buf.extend_from_slice(hash);
    buf.extend_from_slice(data);
    buf
}

/// Parse a message from bytes
pub fn parse(bytes: &[u8]) -> Result<ParsedMessage, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::TooShort);
    }

    match bytes[0] {
        MSG_REQUEST => {
            if bytes.len() < 37 {
                return Err(ParseError::TooShort);
            }
            let id = RequestId::from_le_bytes(bytes[1..5].try_into().unwrap());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[5..37]);
            Ok(ParsedMessage::Request { id, hash })
        }
        MSG_RESPONSE => {
            if bytes.len() < 37 {
                return Err(ParseError::TooShort);
            }
            let id = RequestId::from_le_bytes(bytes[1..5].try_into().unwrap());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[5..37]);
            let data = bytes[37..].to_vec();
            Ok(ParsedMessage::Response { id, hash, data })
        }
        MSG_PUSH => {
            if bytes.len() < 33 {
                return Err(ParseError::TooShort);
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[1..33]);
            let data = bytes[33..].to_vec();
            Ok(ParsedMessage::Push { hash, data })
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
        let bytes = encode_request(123, &hash);
        assert_eq!(bytes.len(), 37);

        match parse(&bytes).unwrap() {
            ParsedMessage::Request { id, hash: h } => {
                assert_eq!(id, 123);
                assert_eq!(h, hash);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let hash = [42u8; 32];
        let data = b"hello world";
        let bytes = encode_response(456, &hash, data);
        assert_eq!(bytes.len(), 37 + data.len());

        match parse(&bytes).unwrap() {
            ParsedMessage::Response { id, hash: h, data: d } => {
                assert_eq!(id, 456);
                assert_eq!(h, hash);
                assert_eq!(d, data);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_push_roundtrip() {
        let hash = [42u8; 32];
        let data = b"pushed data";
        let bytes = encode_push(&hash, data);

        match parse(&bytes).unwrap() {
            ParsedMessage::Push { hash: h, data: d } => {
                assert_eq!(h, hash);
                assert_eq!(d, data);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_parse_garbage() {
        // Empty
        assert!(matches!(parse(&[]), Err(ParseError::TooShort)));

        // Unknown type
        assert!(matches!(parse(&[0xFF]), Err(ParseError::UnknownType(0xFF))));

        // Too short for request
        assert!(matches!(parse(&[MSG_REQUEST, 0, 0]), Err(ParseError::TooShort)));
    }

    #[test]
    fn test_malicious_garbage() {
        // Random garbage bytes - should fail to parse
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(parse(&garbage).is_err());

        // Valid type but truncated
        let mut bad = encode_request(1, &[0u8; 32]);
        bad.truncate(10);
        assert!(parse(&bad).is_err());
    }
}
