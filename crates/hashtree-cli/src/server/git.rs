//! Git smart HTTP protocol routes
//!
//! Provides git fetch/push over HTTP using hashtree-git.
//! Routes:
//!   - GET  /:pubkey/:repo/info/refs?service=git-upload-pack|git-receive-pack
//!   - POST /:pubkey/:repo/git-upload-pack
//!   - POST /:pubkey/:repo/git-receive-pack
//!   - GET  /api/git/repos - list repositories

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
};
use hashtree_git::http::{handle_info_refs, handle_receive_pack, handle_upload_pack, Service};
use hashtree_git::refs::Ref;
use hashtree_git::GitStorage;
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::PublicKey;
use serde_json::json;
use std::sync::Arc;

/// Git endpoint state
#[derive(Clone)]
pub struct GitState {
    pub storage: Arc<GitStorage>,
    /// Local pubkey (hex) - only this pubkey can push
    pub local_pubkey: String,
}

#[derive(serde::Deserialize)]
pub struct InfoRefsQuery {
    service: String,
}

#[derive(serde::Deserialize)]
pub struct GitPath {
    pub pubkey: String,
    pub repo: String,
}

/// Normalize pubkey to hex format (accepts both npub and hex)
fn normalize_pubkey_to_hex(pubkey: &str) -> Option<String> {
    // Try parsing as npub first
    if pubkey.starts_with("npub") {
        PublicKey::from_bech32(pubkey)
            .ok()
            .map(|pk| pk.to_hex())
    } else {
        // Assume hex, validate it
        PublicKey::from_hex(pubkey)
            .ok()
            .map(|pk| pk.to_hex())
    }
}

/// GET /:pubkey/:repo/info/refs?service=git-upload-pack|git-receive-pack
pub async fn info_refs(
    State(state): State<GitState>,
    Path(_path): Path<GitPath>,
    Query(query): Query<InfoRefsQuery>,
) -> Response {
    let service = match Service::from_str(&query.service) {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "Unknown service").into_response();
        }
    };

    match handle_info_refs(&state.storage, service) {
        Ok((content_type, body)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(body))
            .unwrap(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /:pubkey/:repo/git-upload-pack (fetch)
pub async fn upload_pack(
    State(state): State<GitState>,
    Path(_path): Path<GitPath>,
    body: axum::body::Bytes,
) -> Response {
    match handle_upload_pack(&state.storage, &body) {
        Ok(response) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, Service::UploadPack.result_content_type())
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(response))
            .unwrap(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /:pubkey/:repo/git-receive-pack (push)
/// Only allows push if pubkey matches local identity
pub async fn receive_pack(
    State(state): State<GitState>,
    Path(path): Path<GitPath>,
    body: axum::body::Bytes,
) -> Response {
    // Normalize path pubkey to hex for comparison (accepts both npub and hex)
    let path_pubkey_hex = match normalize_pubkey_to_hex(&path.pubkey) {
        Some(hex) => hex,
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid pubkey format").into_response();
        }
    };

    // Only allow push to own pubkey
    if path_pubkey_hex.to_lowercase() != state.local_pubkey.to_lowercase() {
        return (
            StatusCode::FORBIDDEN,
            "Cannot push to another user's repository",
        )
            .into_response();
    }

    match handle_receive_pack(&state.storage, &body) {
        Ok(response) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, Service::ReceivePack.result_content_type())
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(response))
            .unwrap(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// GET /api/git/repos - List git repositories
/// Extracts unique repo names from refs (refs/heads/<branch> per repo)
pub async fn list_repos(State(state): State<GitState>) -> impl IntoResponse {
    // List all refs and extract unique repo names
    // For now we have a single repo, but refs show what branches exist
    let refs = match state.storage.list_refs() {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({
                "error": e.to_string()
            }));
        }
    };

    // Extract branches (refs/heads/*)
    let mut branches: Vec<serde_json::Value> = Vec::new();
    for named_ref in &refs {
        if let Some(branch) = named_ref.name.strip_prefix("refs/heads/") {
            let commit = match &named_ref.reference {
                Ref::Direct(oid) => oid.to_hex(),
                Ref::Symbolic(target) => target.clone(),
            };
            branches.push(json!({
                "name": branch,
                "commit": commit,
            }));
        }
    }

    // Build repo info - currently single repo model
    let has_refs = !refs.is_empty();

    // Convert hex pubkey to npub for display
    let npub = PublicKey::from_hex(&state.local_pubkey)
        .ok()
        .and_then(|pk| pk.to_bech32().ok())
        .unwrap_or_else(|| state.local_pubkey.clone());

    Json(json!({
        "pubkey": npub,
        "has_repo": has_refs,
        "branches": branches,
        "clone_url": format!("/git/{}/repo", npub),
    }))
}
