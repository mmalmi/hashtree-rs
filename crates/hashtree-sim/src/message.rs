//! Message types for simulation
//!
//! Note: These types are used for behavior modeling (e.g., deciding whether
//! to forward requests). Actual networking goes through NetworkAdapter.

use crate::NodeId;

/// Content hash (SHA-256)
pub type Hash = [u8; 32];

/// Request identifier
pub type RequestId = u64;

#[derive(Debug, Clone)]
pub enum Message {
    Request(Request),
    Response(Response),
    Push(Push),
}

#[derive(Debug, Clone)]
pub struct Request {
    pub id: RequestId,
    pub hash: Hash,
    pub origin: NodeId,  // original requester (for metrics)
    pub hops: u32,       // how many nodes forwarded this
    pub ttl: u32,        // max remaining hops
}

#[derive(Debug, Clone)]
pub struct Response {
    pub request_id: RequestId,
    pub hash: Hash,
    pub found: bool,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Push {
    pub hash: Hash,
    pub data: Vec<u8>,
}

impl Request {
    pub fn new(id: RequestId, hash: Hash, origin: NodeId, ttl: u32) -> Self {
        Self {
            id,
            hash,
            origin,
            hops: 0,
            ttl,
        }
    }

    pub fn forwarded(&self) -> Self {
        Self {
            id: self.id,
            hash: self.hash,
            origin: self.origin,
            hops: self.hops + 1,
            ttl: self.ttl.saturating_sub(1),
        }
    }

    pub fn can_forward(&self) -> bool {
        self.ttl > 0
    }
}
