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
use std::time::{SystemTime, UNIX_EPOCH};

use super::auth::AppState;
use super::mime::get_mime_type;

/// Blossom authorization event kind (NIP-98 style)
const BLOSSOM_AUTH_KIND: u16 = 24242;

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
pub async fn cors_preflight() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, PUT, DELETE, OPTIONS")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, Content-Type, *")
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

/// PUT /upload - Upload a new blob (BUD-02)
pub async fn upload_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
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

    // Get content type from header or default
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // Store the blob
    let store_result = store_blossom_blob(&state, &body, &sha256_hex, &auth.pubkey);

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

    // Check ownership - only the uploader can delete
    match state.store.get_blob_owner(&sha256_hex) {
        Ok(Some(owner)) => {
            if owner != auth.pubkey {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                    .header("X-Reason", "Not the blob owner")
                    .body(Body::empty())
                    .unwrap();
            }
        }
        Ok(None) => {
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

    // Delete the blob
    match state.store.delete_blossom_blob(&sha256_hex) {
        Ok(true) => Response::builder()
            .status(StatusCode::OK)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::empty())
            .unwrap(),
        Ok(false) => Response::builder()
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
) -> anyhow::Result<()> {
    // Store as raw blob
    state.store.put_blob(data)?;

    // Create a temporary file and upload through normal path for CID/DAG storage
    let temp_dir = tempfile::tempdir()?;
    let temp_file = temp_dir.path().join(format!("{}.bin", sha256_hex));
    std::fs::write(&temp_file, data)?;

    let _cid = state.store.upload_file(&temp_file)?;

    // Track ownership
    state.store.set_blob_owner(sha256_hex, pubkey)?;

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
