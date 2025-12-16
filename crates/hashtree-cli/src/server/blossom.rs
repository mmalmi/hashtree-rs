//! Blossom protocol implementation (BUD-01, BUD-02)
//!
//! Implements blob storage endpoints with Nostr-based authentication.
//! See: https://github.com/hzrd149/blossom

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Response, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::auth::AppState;
use super::mime::get_mime_type;

/// Social graph root pubkey (sirius - npub1g53mukxnjkcmr94fhryzkqutdz2ukq4ks0gvy5af25rgmwsl4ngq43drvk)
pub const SOCIAL_GRAPH_ROOT: &str = "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";

/// Maximum follow distance for blossom write access (0 = root only, 3 = up to 3rd degree)
pub const MAX_WRITE_DISTANCE: u32 = 3;

/// Ratio threshold for "overmuted" - if muters/followers exceeds this ratio, deny access
/// e.g., 0.1 means if 10% or more of your followers mute you, you're overmuted
pub const OVERMUTED_RATIO: f64 = 0.1;

/// Minimum muter count before ratio check kicks in (avoid edge cases with few followers)
pub const OVERMUTED_MIN_MUTERS: usize = 5;

/// Hardcoded subscriber list - these pubkeys always have write access regardless of social graph
pub static HARDCODED_SUBSCRIBERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "e2bab35b5296ec2242ded0a01f6d6723a5cd921239280c0a5f0b5589303336b6",
        "040ab8ad2ab2447f2a702903553eb56820a6799a3edc4a6d3816e0cc41fea7f8",
        "1faee0e854e848af26060f6ad40d278d882bb8b8f1c474b25e2f95c7fee1ac9d",
        "df410c7a4dac30eec2437d39911e1cf812f3f6aae3f628da40e3190b582db9dc",
        "4408b61d584b7a48373d1b2f05bc30fed614f316da272b984b4d587522470502",
        "6eef2e68c399c8f2efbf70d831c2b618d7a84bdfd21734a81e6d7d3d817f6850",
        "0ab915c92977c66b57c6bf64d58252db46e5d027ad2c7e1aac9aa3b4bc2ae379",
        "2f372b6c2d615a91c9248f87417525dc202dfbb37ffea5cd2f182d7fc1ef514a",
        "65f13e7c23321cb09909ef08da71c6d9bc44f390a92783e78b930609ab370ac9",
        "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0", // root
    ])
});

/// Blossom authorization event kind (NIP-98 style)
const BLOSSOM_AUTH_KIND: u16 = 24242;

/// Default maximum upload size in bytes (5 MB)
pub const DEFAULT_MAX_UPLOAD_SIZE: usize = 5 * 1024 * 1024;

/// Check if a user is "overmuted" based on their muter/follower ratio
/// Returns true if the mute ratio exceeds the threshold
pub fn is_overmuted(muter_count: usize, followers_count: usize) -> bool {
    if muter_count < OVERMUTED_MIN_MUTERS || followers_count == 0 {
        return false;
    }
    let mute_ratio = muter_count as f64 / followers_count as f64;
    mute_ratio >= OVERMUTED_RATIO
}

/// Check if a pubkey has write access based on social graph distance
/// Returns Ok(()) if allowed, Err with JSON error body if denied
fn check_write_access(state: &AppState, pubkey: &str) -> Result<(), Response<Body>> {
    // Always allow hardcoded subscribers
    if HARDCODED_SUBSCRIBERS.contains(pubkey) {
        tracing::debug!("Blossom write allowed for {}... (subscriber)", &pubkey[..8]);
        return Ok(());
    }

    // Always allow root
    if pubkey == SOCIAL_GRAPH_ROOT {
        tracing::debug!("Blossom write allowed for {}... (root)", &pubkey[..8]);
        return Ok(());
    }

    // Check social graph distance via ndb_query
    let Some(ref ndb_query) = state.ndb_query else {
        // No social graph configured - deny by default for safety
        tracing::warn!("Blossom write denied for {}... (no social graph)", &pubkey[..8]);
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"Write access requires social graph authentication. You must be within 3 degrees of separation from the server operator, or be a subscriber."}"#))
            .unwrap());
    };

    // Convert pubkey hex to bytes
    let pubkey_bytes: [u8; 32] = match hex::decode(pubkey) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            tracing::warn!("Blossom write denied: invalid pubkey format");
            return Err(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"Invalid pubkey format"}"#))
                .unwrap());
        }
    };

    // Check if muted by root first
    match ndb_query.is_muted_by_root(pubkey_bytes) {
        Ok(true) => {
            tracing::info!("Blossom write denied for {}... (muted by root)", &pubkey[..8]);
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"Access denied. You have been muted by the server operator."}"#))
                .unwrap());
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!("Mute check failed for {}...: {}", &pubkey[..8], e);
            // Continue with other checks even if mute check fails
        }
    }

    // Query social graph stats (includes muter_count for overmuted check)
    match ndb_query.socialgraph_stats(pubkey_bytes) {
        Ok(stats) => {
            // Check if overmuted (muter/follower ratio too high)
            if is_overmuted(stats.muter_count, stats.followers_count) {
                let mute_ratio = stats.muter_count as f64 / stats.followers_count as f64;
                tracing::info!(
                    "Blossom write denied for {}... (overmuted: {}/{} = {:.1}% >= {:.1}%)",
                    &pubkey[..8],
                    stats.muter_count,
                    stats.followers_count,
                    mute_ratio * 100.0,
                    OVERMUTED_RATIO * 100.0
                );
                return Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"error":"Access denied. Your mute ratio is too high ({} muters / {} followers = {:.1}%, threshold: {:.1}%)."}}""#,
                        stats.muter_count, stats.followers_count, mute_ratio * 100.0, OVERMUTED_RATIO * 100.0
                    )))
                    .unwrap());
            }

            // Check follow distance (u32::MAX or very high value means not in graph)
            if stats.follow_distance <= MAX_WRITE_DISTANCE {
                tracing::debug!(
                    "Blossom write allowed for {}... (distance: {}, muters: {})",
                    &pubkey[..8],
                    stats.follow_distance,
                    stats.muter_count
                );
                Ok(())
            } else {
                tracing::info!(
                    "Blossom write denied for {}... (distance: {} > max: {})",
                    &pubkey[..8],
                    stats.follow_distance,
                    MAX_WRITE_DISTANCE
                );
                Err(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"error":"Not authorized. Your follow distance is {} but max allowed is {}. You need to be within {} degrees of separation from npub1g53mukxnjkcmr94fhryzkqutdz2ukq4ks0gvy5af25rgmwsl4ngq43drvk (follow them or be followed by someone they follow)."}}"#,
                        stats.follow_distance, MAX_WRITE_DISTANCE, MAX_WRITE_DISTANCE
                    )))
                    .unwrap())
            }
        }
        Err(e) => {
            tracing::error!("Social graph query failed for {}...: {}", &pubkey[..8], e);
            Err(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"Social graph query failed"}"#))
                .unwrap())
        }
    }
}

/// Blob descriptor returned by upload and list endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub mime_type: String,
    pub uploaded: u64,
}

/// Query parameters for list endpoint
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

/// Parsed Nostr authorization event
#[derive(Debug)]
pub struct BlossomAuth {
    pub pubkey: String,
    pub kind: u16,
    pub created_at: u64,
    pub expiration: Option<u64>,
    pub action: Option<String>,       // "upload", "delete", "list", "get"
    pub blob_hashes: Vec<String>,     // x tags
    pub server: Option<String>,       // server tag
}

/// Parse and verify Nostr authorization from header
/// Returns the verified auth or an error response
pub fn verify_blossom_auth(
    headers: &HeaderMap,
    required_action: &str,
    required_hash: Option<&str>,
) -> Result<BlossomAuth, (StatusCode, &'static str)> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let nostr_event = auth_header
        .strip_prefix("Nostr ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid auth scheme, expected 'Nostr'"))?;

    // Decode base64 event
    let engine = base64::engine::general_purpose::STANDARD;
    let event_bytes = engine
        .decode(nostr_event)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid base64 in auth header"))?;

    let event_json: serde_json::Value = serde_json::from_slice(&event_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON in auth event"))?;

    // Extract event fields
    let kind = event_json["kind"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "Missing kind in event"))?;

    if kind != BLOSSOM_AUTH_KIND as u64 {
        return Err((StatusCode::BAD_REQUEST, "Invalid event kind, expected 24242"));
    }

    let pubkey = event_json["pubkey"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing pubkey in event"))?
        .to_string();

    let created_at = event_json["created_at"]
        .as_u64()
        .ok_or((StatusCode::BAD_REQUEST, "Missing created_at in event"))?;

    let sig = event_json["sig"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing signature in event"))?;

    // Verify signature
    if !verify_nostr_signature(&event_json, &pubkey, sig) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid signature"));
    }

    // Parse tags
    let tags = event_json["tags"]
        .as_array()
        .ok_or((StatusCode::BAD_REQUEST, "Missing tags in event"))?;

    let mut expiration: Option<u64> = None;
    let mut action: Option<String> = None;
    let mut blob_hashes: Vec<String> = Vec::new();
    let mut server: Option<String> = None;

    for tag in tags {
        let tag_arr = tag.as_array();
        if let Some(arr) = tag_arr {
            if arr.len() >= 2 {
                let tag_name = arr[0].as_str().unwrap_or("");
                let tag_value = arr[1].as_str().unwrap_or("");

                match tag_name {
                    "t" => action = Some(tag_value.to_string()),
                    "x" => blob_hashes.push(tag_value.to_lowercase()),
                    "expiration" => expiration = tag_value.parse().ok(),
                    "server" => server = Some(tag_value.to_string()),
                    _ => {}
                }
            }
        }
    }

    // Validate expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Some(exp) = expiration {
        if exp < now {
            return Err((StatusCode::UNAUTHORIZED, "Authorization expired"));
        }
    }

    // Validate created_at is not in the future (with 60s tolerance)
    if created_at > now + 60 {
        return Err((StatusCode::BAD_REQUEST, "Event created_at is in the future"));
    }

    // Validate action matches
    if let Some(ref act) = action {
        if act != required_action {
            return Err((StatusCode::FORBIDDEN, "Action mismatch"));
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, "Missing 't' tag for action"));
    }

    // Validate hash if required
    if let Some(hash) = required_hash {
        if !blob_hashes.is_empty() && !blob_hashes.contains(&hash.to_lowercase()) {
            return Err((StatusCode::FORBIDDEN, "Blob hash not authorized"));
        }
    }

    Ok(BlossomAuth {
        pubkey,
        kind: kind as u16,
        created_at,
        expiration,
        action,
        blob_hashes,
        server,
    })
}

/// Verify Nostr event signature using secp256k1
fn verify_nostr_signature(event: &serde_json::Value, pubkey: &str, sig: &str) -> bool {
    use secp256k1::{Message, Secp256k1, schnorr::Signature, XOnlyPublicKey};

    // Compute event ID (sha256 of serialized event)
    let content = event["content"].as_str().unwrap_or("");
    let full_serialized = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        pubkey,
        event["created_at"],
        event["kind"],
        event["tags"],
        escape_json_string(content),
    );

    let mut hasher = Sha256::new();
    hasher.update(full_serialized.as_bytes());
    let event_id = hasher.finalize();

    // Parse pubkey and signature
    let pubkey_bytes = match hex::decode(pubkey) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(sig) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let secp = Secp256k1::verification_only();

    let xonly_pubkey = match XOnlyPublicKey::from_slice(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let message = match Message::from_digest_slice(&event_id) {
        Ok(m) => m,
        Err(_) => return false,
    };

    secp.verify_schnorr(&signature, &message, &xonly_pubkey).is_ok()
}

/// Escape string for JSON serialization
fn escape_json_string(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// CORS preflight handler for all Blossom endpoints
/// Echoes back Access-Control-Request-Headers to allow any headers
pub async fn cors_preflight(headers: HeaderMap) -> impl IntoResponse {
    // Echo back requested headers, or use sensible defaults that cover common Blossom headers
    let allowed_headers = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Authorization, Content-Type, X-SHA-256, x-sha-256");

    // Always include common headers in addition to what was requested
    let full_allowed = format!(
        "{}, Authorization, Content-Type, X-SHA-256, x-sha-256, Accept, Cache-Control",
        allowed_headers
    );

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, PUT, DELETE, OPTIONS")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, full_allowed)
        .header(header::ACCESS_CONTROL_MAX_AGE, "86400")
        .body(Body::empty())
        .unwrap()
}

/// HEAD /<sha256> - Check if blob exists
pub async fn head_blob(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let (hash_part, ext) = parse_hash_and_extension(&id);

    if !is_valid_sha256(&hash_part) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Invalid SHA256 hash")
            .body(Body::empty())
            .unwrap();
    }

    let sha256_hex = hash_part.to_lowercase();

    // Check if blob exists via CID lookup
    match state.store.get_cid_by_sha256(&sha256_hex) {
        Ok(Some(cid)) => {
            // Get file size and mime type
            let (size, mime_type) = get_blob_metadata(&state, &cid, ext);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CONTENT_LENGTH, size)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Ok(None) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Blob not found")
            .body(Body::empty())
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::empty())
            .unwrap(),
    }
}

/// Check if a MIME type is browser-viewable media (image/video/audio)
/// These require social graph access, while application/* types are open to everyone
fn is_browser_viewable_media(content_type: &str) -> bool {
    let ct_lower = content_type.to_lowercase();
    ct_lower.starts_with("image/")
        || ct_lower.starts_with("video/")
        || ct_lower.starts_with("audio/")
}

/// PUT /upload - Upload a new blob (BUD-02)
pub async fn upload_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Check size limit first (before auth to save resources)
    let max_size = state.max_upload_bytes;
    if body.len() > max_size {
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"error":"Upload size {} bytes exceeds maximum {} bytes ({} MB)"}}"#,
                body.len(),
                max_size,
                max_size / 1024 / 1024
            )))
            .unwrap();
    }

    // Verify authorization
    let auth = match verify_blossom_auth(&headers, "upload", None) {
        Ok(a) => a,
        Err((status, reason)) => {
            return Response::builder()
                .status(status)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header("X-Reason", reason)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(r#"{{"error":"{}"}}"#, reason)))
                .unwrap();
        }
    };

    // Get content type from header
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Check social graph access control based on public_writes setting and content type
    // When public_writes=true (default): only browser-viewable media requires social graph
    // When public_writes=false: all uploads require social graph
    let requires_social_graph = if state.public_writes {
        // Only media files require social graph check when public writes enabled
        is_browser_viewable_media(&content_type)
    } else {
        // All uploads require social graph when public writes disabled
        true
    };

    // Check if user is in social graph (for ownership tracking, even if upload is allowed)
    let is_in_social_graph = check_write_access(&state, &auth.pubkey).is_ok();

    if requires_social_graph && !is_in_social_graph {
        // Must be in social graph for media uploads
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"Media uploads require social graph membership"}"#))
            .unwrap();
    }

    // Compute SHA256 of uploaded data
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let sha256_bytes = hasher.finalize();
    let sha256_hex = hex::encode(sha256_bytes);

    // If auth has x tags, verify hash matches
    if !auth.blob_hashes.is_empty() && !auth.blob_hashes.contains(&sha256_hex) {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Uploaded blob hash does not match authorized hash")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"Hash mismatch"}"#))
            .unwrap();
    }

    let size = body.len() as u64;

    // Store the blob (only track ownership if user is in social graph)
    let store_result = store_blossom_blob(&state, &body, &sha256_hex, &auth.pubkey, is_in_social_graph);

    match store_result {
        Ok(()) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Determine file extension from content type
            let ext = mime_to_extension(&content_type);

            let descriptor = BlobDescriptor {
                url: format!("/{}{}", sha256_hex, ext),
                sha256: sha256_hex,
                size,
                mime_type: content_type,
                uploaded: now,
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&descriptor).unwrap()))
                .unwrap()
        }
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Storage error")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(r#"{{"error":"{}"}}"#, e)))
            .unwrap(),
    }
}

/// DELETE /<sha256> - Delete a blob (BUD-02)
/// Note: Blob is only fully deleted when ALL owners have removed it
pub async fn delete_blob(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (hash_part, _) = parse_hash_and_extension(&id);

    if !is_valid_sha256(&hash_part) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Invalid SHA256 hash")
            .body(Body::empty())
            .unwrap();
    }

    let sha256_hex = hash_part.to_lowercase();

    // Verify authorization with hash requirement
    let auth = match verify_blossom_auth(&headers, "delete", Some(&sha256_hex)) {
        Ok(a) => a,
        Err((status, reason)) => {
            return Response::builder()
                .status(status)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header("X-Reason", reason)
                .body(Body::empty())
                .unwrap();
        }
    };

    // Check ownership - user must be one of the owners (O(1) lookup with composite key)
    match state.store.is_blob_owner(&sha256_hex, &auth.pubkey) {
        Ok(true) => {
            // User is an owner, proceed with delete
        }
        Ok(false) => {
            // Check if blob exists at all (for proper error message)
            match state.store.blob_has_owners(&sha256_hex) {
                Ok(true) => {
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .header("X-Reason", "Not a blob owner")
                        .body(Body::empty())
                        .unwrap();
                }
                Ok(false) => {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .header("X-Reason", "Blob not found")
                        .body(Body::empty())
                        .unwrap();
                }
                Err(_) => {
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(Body::empty())
                        .unwrap();
                }
            }
        }
        Err(_) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap();
        }
    }

    // Remove this user's ownership (blob only deleted when no owners remain)
    match state.store.delete_blossom_blob(&sha256_hex, &auth.pubkey) {
        Ok(fully_deleted) => {
            // Return 200 OK whether blob was fully deleted or just removed from user's list
            // The client doesn't need to know if other owners still exist
            Response::builder()
                .status(StatusCode::OK)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header("X-Blob-Deleted", if fully_deleted { "true" } else { "false" })
                .body(Body::empty())
                .unwrap()
        }
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::empty())
            .unwrap(),
    }
}

/// GET /list/<pubkey> - List blobs for a pubkey (BUD-02)
pub async fn list_blobs(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Validate pubkey format (64 hex chars)
    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header("X-Reason", "Invalid pubkey format")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("[]"))
            .unwrap();
    }

    let pubkey_hex = pubkey.to_lowercase();

    // Optional auth verification for list
    let _auth = verify_blossom_auth(&headers, "list", None).ok();

    // Get blobs for this pubkey
    match state.store.list_blobs_by_pubkey(&pubkey_hex) {
        Ok(blobs) => {
            // Apply filters
            let mut filtered: Vec<_> = blobs
                .into_iter()
                .filter(|b| {
                    if let Some(since) = query.since {
                        if b.uploaded < since {
                            return false;
                        }
                    }
                    if let Some(until) = query.until {
                        if b.uploaded > until {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            // Sort by uploaded descending (most recent first)
            filtered.sort_by(|a, b| b.uploaded.cmp(&a.uploaded));

            // Apply limit
            let limit = query.limit.unwrap_or(100).min(1000);
            filtered.truncate(limit);

            Response::builder()
                .status(StatusCode::OK)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&filtered).unwrap()))
                .unwrap()
        }
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("[]"))
            .unwrap(),
    }
}

// Helper functions

fn parse_hash_and_extension(id: &str) -> (&str, Option<&str>) {
    if let Some(dot_pos) = id.rfind('.') {
        (&id[..dot_pos], Some(&id[dot_pos..]))
    } else {
        (id, None)
    }
}

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn get_blob_metadata(state: &AppState, cid: &str, ext: Option<&str>) -> (u64, String) {
    let size = state
        .store
        .get_file_chunk_metadata(cid)
        .ok()
        .flatten()
        .map(|m| m.total_size)
        .unwrap_or(0);

    // Use extension for MIME type if provided, otherwise default to octet-stream
    // (hashtree doesn't store filenames in tree nodes)
    let mime_type = ext
        .map(|e| get_mime_type(&format!("file{}", e)))
        .unwrap_or("application/octet-stream")
        .to_string();

    (size, mime_type)
}

fn store_blossom_blob(
    state: &AppState,
    data: &[u8],
    sha256_hex: &str,
    pubkey: &str,
    track_ownership: bool,
) -> anyhow::Result<()> {
    // Store as raw blob
    state.store.put_blob(data)?;

    // Create a temporary file and upload through normal path for CID/DAG storage
    let temp_dir = tempfile::tempdir()?;
    let temp_file = temp_dir.path().join(format!("{}.bin", sha256_hex));
    std::fs::write(&temp_file, data)?;

    // Don't auto-pin blossom uploads - they can be evicted like other synced content
    let _cid = state.store.upload_file_no_pin(&temp_file)?;

    // Only track ownership for social graph members
    // Non-members can upload (if public_writes=true) but can't delete
    if track_ownership {
        state.store.set_blob_owner(sha256_hex, pubkey)?;
    }

    Ok(())
}

fn mime_to_extension(mime: &str) -> &'static str {
    match mime {
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "image/svg+xml" => ".svg",
        "video/mp4" => ".mp4",
        "video/webm" => ".webm",
        "audio/mpeg" => ".mp3",
        "audio/ogg" => ".ogg",
        "application/pdf" => ".pdf",
        "text/plain" => ".txt",
        "text/html" => ".html",
        "application/json" => ".json",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardcoded_subscribers_allowed() {
        // All hardcoded subscribers should be in the set
        assert!(HARDCODED_SUBSCRIBERS.contains("e2bab35b5296ec2242ded0a01f6d6723a5cd921239280c0a5f0b5589303336b6"));
        assert!(HARDCODED_SUBSCRIBERS.contains("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0")); // root

        // Unknown pubkey should not be in the set
        assert!(!HARDCODED_SUBSCRIBERS.contains("0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_social_graph_root_constant() {
        // Root pubkey should be the correct hex for npub1g53mukxnjkcmr94fhryzkqutdz2ukq4ks0gvy5af25rgmwsl4ngq43drvk
        assert_eq!(SOCIAL_GRAPH_ROOT, "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0");
        assert_eq!(SOCIAL_GRAPH_ROOT.len(), 64);
    }

    #[test]
    fn test_max_write_distance() {
        // 3 degrees of separation
        assert_eq!(MAX_WRITE_DISTANCE, 3);
    }

    #[test]
    fn test_is_valid_sha256() {
        assert!(is_valid_sha256("e2bab35b5296ec2242ded0a01f6d6723a5cd921239280c0a5f0b5589303336b6"));
        assert!(is_valid_sha256("0000000000000000000000000000000000000000000000000000000000000000"));

        // Too short
        assert!(!is_valid_sha256("e2bab35b5296ec2242ded0a01f6d6723"));
        // Too long
        assert!(!is_valid_sha256("e2bab35b5296ec2242ded0a01f6d6723a5cd921239280c0a5f0b5589303336b6aa"));
        // Invalid chars
        assert!(!is_valid_sha256("zzbab35b5296ec2242ded0a01f6d6723a5cd921239280c0a5f0b5589303336b6"));
        // Empty
        assert!(!is_valid_sha256(""));
    }

    #[test]
    fn test_parse_hash_and_extension() {
        let (hash, ext) = parse_hash_and_extension("abc123.png");
        assert_eq!(hash, "abc123");
        assert_eq!(ext, Some(".png"));

        let (hash2, ext2) = parse_hash_and_extension("abc123");
        assert_eq!(hash2, "abc123");
        assert_eq!(ext2, None);

        let (hash3, ext3) = parse_hash_and_extension("abc.123.jpg");
        assert_eq!(hash3, "abc.123");
        assert_eq!(ext3, Some(".jpg"));
    }

    #[test]
    fn test_mime_to_extension() {
        assert_eq!(mime_to_extension("image/png"), ".png");
        assert_eq!(mime_to_extension("image/jpeg"), ".jpg");
        assert_eq!(mime_to_extension("video/mp4"), ".mp4");
        assert_eq!(mime_to_extension("application/octet-stream"), "");
        assert_eq!(mime_to_extension("unknown/type"), "");
    }

    #[test]
    fn test_is_overmuted() {
        // Not enough muters - should not be overmuted
        assert!(!is_overmuted(0, 100));
        assert!(!is_overmuted(4, 100)); // Below OVERMUTED_MIN_MUTERS (5)

        // Zero followers - should not be overmuted (avoid div by zero)
        assert!(!is_overmuted(10, 0));

        // Normal ratio - should not be overmuted
        assert!(!is_overmuted(5, 100));  // 5% < 10%
        assert!(!is_overmuted(9, 100));  // 9% < 10%

        // High ratio - should be overmuted
        assert!(is_overmuted(10, 100));  // 10% >= 10%
        assert!(is_overmuted(20, 100));  // 20% >= 10%
        assert!(is_overmuted(50, 100));  // 50% >= 10%

        // Edge cases
        assert!(is_overmuted(5, 50));    // 10% exactly
        assert!(is_overmuted(10, 50));   // 20%
        assert!(!is_overmuted(5, 51));   // 9.8% < 10%
    }

    #[test]
    fn test_overmuted_constants() {
        // Verify threshold constants are reasonable
        assert_eq!(OVERMUTED_RATIO, 0.1); // 10%
        assert_eq!(OVERMUTED_MIN_MUTERS, 5);
    }

    #[test]
    fn test_is_browser_viewable_media() {
        // Browser-viewable media - require social graph
        assert!(is_browser_viewable_media("image/png"));
        assert!(is_browser_viewable_media("image/jpeg"));
        assert!(is_browser_viewable_media("image/gif"));
        assert!(is_browser_viewable_media("image/webp"));
        assert!(is_browser_viewable_media("image/svg+xml"));
        assert!(is_browser_viewable_media("video/mp4"));
        assert!(is_browser_viewable_media("video/webm"));
        assert!(is_browser_viewable_media("audio/mpeg"));
        assert!(is_browser_viewable_media("audio/ogg"));
        assert!(is_browser_viewable_media("audio/wav"));

        // Case insensitive
        assert!(is_browser_viewable_media("Image/PNG"));
        assert!(is_browser_viewable_media("VIDEO/MP4"));

        // Non-media - open to everyone
        assert!(!is_browser_viewable_media("application/octet-stream"));
        assert!(!is_browser_viewable_media("application/json"));
        assert!(!is_browser_viewable_media("application/zip"));
        assert!(!is_browser_viewable_media("application/pdf"));
        assert!(!is_browser_viewable_media("text/plain"));
        assert!(!is_browser_viewable_media("text/html"));
        assert!(!is_browser_viewable_media(""));
    }
}
