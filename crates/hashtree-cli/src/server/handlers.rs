use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, Response, StatusCode},
    response::{IntoResponse, Json},
};
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use hashtree::{nhash_decode, to_hex};
use hashtree_resolver::{nostr::{NostrRootResolver, NostrResolverConfig}, RootResolver};
use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use super::auth::AppState;
use super::mime::get_mime_type;
use super::ui::{root_page, serve_directory_html, serve_directory_json};

pub async fn serve_root() -> impl IntoResponse {
    root_page()
}

/// Internal content serving (shared by CID and blossom routes)
async fn serve_content_internal(
    state: &AppState,
    cid: &str,
    headers: axum::http::HeaderMap,
) -> Response<Body> {
    let store = &state.store;

    // Check if it's a directory (with actual entries)
    if let Ok(Some(listing)) = store.get_directory_listing(cid) {
        // Only serve as directory if it has entries (not an empty file DAG)
        if !listing.entries.is_empty() {
            // Check if browser (wants HTML)
            let wants_html = headers
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("text/html"))
                .unwrap_or(false);

            if wants_html {
                return serve_directory_html(cid, &listing.dir_name, listing.entries).into_response();
            } else {
                return serve_directory_json(&listing.dir_name, listing.entries).into_response();
            }
        }
    }

    // Try as file
    // Check for Range header
    let range_header = headers.get(header::RANGE).and_then(|v| v.to_str().ok());

    if let Some(range_str) = range_header {
        // Parse Range: bytes=start-end
        if let Some(bytes_range) = range_str.strip_prefix("bytes=") {
            let parts: Vec<&str> = bytes_range.split('-').collect();
            if parts.len() == 2 {
                if let Ok(start) = parts[0].parse::<u64>() {
                    let end = if parts[1].is_empty() {
                        None
                    } else {
                        parts[1].parse::<u64>().ok()
                    };

                    // Content type - hashtree doesn't store filenames, so default to octet-stream
                    let content_type = "application/octet-stream";

                    // Get metadata to determine total size
                    match store.get_file_chunk_metadata(cid) {
                        Ok(Some(metadata)) => {
                            let total_size = metadata.total_size;

                            if start >= total_size {
                                return Response::builder()
                                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                    .header(header::CONTENT_TYPE, "text/plain")
                                    .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                    .body(Body::from("Range not satisfiable"))
                                    .unwrap()
                                    .into_response();
                            }

                            let end_actual = end.unwrap_or(total_size - 1).min(total_size - 1);
                            let content_length = end_actual - start + 1;
                            let content_range = format!("bytes {}-{}/{}", start, end_actual, total_size);

                            // Use streaming for chunked files
                            if metadata.is_chunked {
                                match state.store.clone().stream_file_range_chunks_owned(cid, start, end_actual) {
                                    Ok(Some(chunks_iter)) => {
                                        let stream = stream::iter(chunks_iter)
                                            .map(|result| result.map(Bytes::from));

                                        return Response::builder()
                                            .status(StatusCode::PARTIAL_CONTENT)
                                            .header(header::CONTENT_TYPE, content_type)
                                            .header(header::CONTENT_LENGTH, content_length)
                                            .header(header::CONTENT_RANGE, content_range)
                                            .header(header::ACCEPT_RANGES, "bytes")
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from_stream(stream))
                                            .unwrap()
                                            .into_response();
                                    }
                                    Ok(None) => {
                                        return Response::builder()
                                            .status(StatusCode::NOT_FOUND)
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from("File not found"))
                                            .unwrap()
                                            .into_response();
                                    }
                                    Err(e) => {
                                        return Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from(format!("Error: {}", e)))
                                            .unwrap()
                                            .into_response();
                                    }
                                }
                            } else {
                                // For small non-chunked files, use buffered approach
                                match store.get_file_range(cid, start, Some(end_actual)) {
                                    Ok(Some((range_content, _))) => {
                                        return Response::builder()
                                            .status(StatusCode::PARTIAL_CONTENT)
                                            .header(header::CONTENT_TYPE, content_type)
                                            .header(header::CONTENT_LENGTH, range_content.len())
                                            .header(header::CONTENT_RANGE, content_range)
                                            .header(header::ACCEPT_RANGES, "bytes")
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from(range_content))
                                            .unwrap()
                                            .into_response();
                                    }
                                    Ok(None) => {
                                        return Response::builder()
                                            .status(StatusCode::NOT_FOUND)
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from("File not found"))
                                            .unwrap()
                                            .into_response();
                                    }
                                    Err(e) => {
                                        return Response::builder()
                                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                                            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                            .body(Body::from(format!("Error: {}", e)))
                                            .unwrap()
                                            .into_response();
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            return Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                .body(Body::from("File not found"))
                                .unwrap()
                                .into_response();
                        }
                        Err(e) => {
                            return Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                                .body(Body::from(format!("Error: {}", e)))
                                .unwrap()
                                .into_response();
                        }
                    }
                }
            }
        }
    }

    // Fall back to full file
    match store.get_file(cid) {
        Ok(Some(content)) => {
            // Content type - hashtree doesn't store filenames, so default to octet-stream
            let content_type = "application/octet-stream";

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, content.len())
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(content))
                .unwrap()
                .into_response()
        }
        Ok(None) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::from("Not found"))
            .unwrap()
            .into_response(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::from(format!("Error: {}", e)))
            .unwrap()
            .into_response(),
    }
}

/// Serve content by CID or blossom SHA256 hash
/// Tries CID first, then falls back to blossom lookup if input looks like SHA256
pub async fn serve_content_or_blob(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Parse potential extension for blossom
    let (hash_part, _ext) = if let Some(dot_pos) = id.rfind('.') {
        (&id[..dot_pos], Some(&id[dot_pos..]))
    } else {
        (id.as_str(), None)
    };

    // Check if it looks like a SHA256 hash (64 hex chars)
    let is_sha256 = hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit());

    // Always try direct CID/hash lookup first
    // (hashtree hashes are 64 hex chars, same as blossom SHA256)
    if state.store.get_file_chunk_metadata(&id).ok().flatten().is_some() {
        return serve_content_internal(&state, &id, headers).await;
    }

    // Try blossom SHA256 lookup (content hash -> root hash mapping)
    if is_sha256 {
        let sha256_hex = hash_part.to_lowercase();
        if let Ok(Some(cid)) = state.store.get_cid_by_sha256(&sha256_hex) {
            return serve_content_internal(&state, &cid, headers).await;
        }
    }

    // Not found in either
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(Body::from("Not found"))
        .unwrap()
        .into_response()
}

/// Serve content by nhash (bech32 encoded hash)
/// Route: /nhash1... (the "nhash1" prefix is matched by the route, :rest captures the remainder)
pub async fn serve_nhash(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Reconstruct full nhash (route strips the prefix)
    let nhash = format!("nhash1{}", rest);

    match nhash_decode(&nhash) {
        Ok(nhash_data) => {
            let hash_hex = to_hex(&nhash_data.hash);
            // TODO: handle decryption key if present in nhash_data.decrypt_key
            serve_content_internal(&state, &hash_hex, headers).await
        }
        Err(e) => {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(format!("Invalid nhash: {}", e)))
                .unwrap()
                .into_response()
        }
    }
}

/// Serve content by npub/ref_name (Nostr resolver)
/// Route: /npub1... (the "npub1" prefix is matched by the route, :rest captures pubkey remainder + /ref)
pub async fn serve_npub(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Reconstruct full key: "npub1" + rest (e.g., "abc.../mydata")
    let key = format!("npub1{}", rest);

    // Validate format: must have a / for ref name
    if !key.contains('/') {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::from("Missing ref name: use /npub1.../ref_name"))
            .unwrap()
            .into_response();
    }

    let resolver = match NostrRootResolver::new(resolver_config()).await {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(format!("Failed to create resolver: {}", e)))
                .unwrap()
                .into_response();
        }
    };

    match tokio::time::timeout(HTTP_RESOLVER_TIMEOUT, resolver.resolve_wait(&key)).await {
        Ok(Ok(cid)) => {
            let hash_hex = to_hex(&cid.hash);
            let _ = resolver.stop().await;
            serve_content_internal(&state, &hash_hex, headers).await
        }
        Ok(Err(e)) => {
            let _ = resolver.stop().await;
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(format!("Resolution failed: {}", e)))
                .unwrap()
                .into_response()
        }
        Err(_) => {
            let _ = resolver.stop().await;
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from("Resolution timeout"))
                .unwrap()
                .into_response()
        }
    }
}

pub async fn upload_file(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let store = &state.store;
    let mut temp_file_path: Option<std::path::PathBuf> = None;
    let mut file_name_final: Option<String> = None;
    let temp_dir = tempfile::tempdir().unwrap();

    while let Some(mut field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let file_name = field.file_name().unwrap_or("upload").to_string();
            let temp_file = temp_dir.path().join(&file_name);

            // Stream directly to disk instead of loading into memory
            let mut file = tokio::fs::File::create(&temp_file).await.unwrap();

            while let Some(chunk) = field.next().await {
                if let Ok(data) = chunk {
                    file.write_all(&data).await.unwrap();
                }
            }

            file.flush().await.unwrap();
            temp_file_path = Some(temp_file);
            file_name_final = Some(file_name);
            break;
        }
    }

    let (temp_file, file_name) = match (temp_file_path, file_name_final) {
        (Some(path), Some(name)) => (path, name),
        _ => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("No file provided"))
                .unwrap();
        }
    };

    // Use streaming upload for files > 10MB
    let file_size = std::fs::metadata(&temp_file).ok().map(|m| m.len()).unwrap_or(0);
    let use_streaming = file_size > 10 * 1024 * 1024;

    let cid_result = if use_streaming {
        // Streaming upload with progress callbacks
        let file = std::fs::File::open(&temp_file).unwrap();
        store.upload_file_stream(file, file_name, |_intermediate_cid| {
            // Could log progress here or publish to websocket
        })
    } else {
        // Regular upload for small files
        store.upload_file(&temp_file)
    };

    // Upload and get CID
    match cid_result {
        Ok(cid) => {
            let json = json!({
                "success": true,
                "cid": cid
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
        Err(e) => {
            let json = json!({
                "success": false,
                "error": e.to_string()
            });
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap()
        }
    }
}

pub async fn list_pins(State(state): State<AppState>) -> impl IntoResponse {
    let store = &state.store;
    match store.list_pins_with_names() {
        Ok(pins) => Json(json!({
            "pins": pins.iter().map(|p| json!({
                "cid": p.cid,
                "name": p.name,
                "is_directory": p.is_directory
            })).collect::<Vec<_>>()
        })),
        Err(e) => Json(json!({
            "error": e.to_string()
        })),
    }
}

pub async fn pin_cid(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> impl IntoResponse {
    let store = &state.store;
    match store.pin(&cid) {
        Ok(_) => Json(json!({
            "success": true,
            "cid": cid
        })),
        Err(e) => Json(json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub async fn unpin_cid(
    State(state): State<AppState>,
    Path(cid): Path<String>,
) -> impl IntoResponse {
    let store = &state.store;
    match store.unpin(&cid) {
        Ok(_) => Json(json!({
            "success": true,
            "cid": cid
        })),
        Err(e) => Json(json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

pub async fn storage_stats(State(state): State<AppState>) -> impl IntoResponse {
    let store = &state.store;
    match store.get_storage_stats() {
        Ok(stats) => Json(json!({
            "total_dags": stats.total_dags,
            "pinned_dags": stats.pinned_dags,
            "total_bytes": stats.total_bytes,
        })),
        Err(e) => Json(json!({
            "error": e.to_string()
        })),
    }
}

pub async fn garbage_collect(State(state): State<AppState>) -> impl IntoResponse {
    let store = &state.store;
    match store.gc() {
        Ok(gc_stats) => Json(json!({
            "deleted_dags": gc_stats.deleted_dags,
            "freed_bytes": gc_stats.freed_bytes
        })),
        Err(e) => Json(json!({
            "error": e.to_string()
        })),
    }
}

pub async fn socialgraph_stats(State(state): State<AppState>) -> impl IntoResponse {
    let Some(query) = &state.ndb_query else {
        return Json(json!({
            "error": "nostrdb not configured"
        }));
    };

    // Query social graph stats for root user via channel to ndb thread
    match query.socialgraph_root_stats() {
        Ok(stats) => Json(json!({
            "following_count": stats.following_count,
            "followers_count": stats.followers_count,
            "follow_distance": stats.follow_distance,
        })),
        Err(e) => Json(json!({
            "error": e.to_string()
        })),
    }
}

/// Timeout for HTTP resolver requests
const HTTP_RESOLVER_TIMEOUT: Duration = Duration::from_secs(10);

/// Create resolver config with HTTP timeout
fn resolver_config() -> NostrResolverConfig {
    NostrResolverConfig {
        resolve_timeout: HTTP_RESOLVER_TIMEOUT,
        ..Default::default()
    }
}

/// Resolve npub/treename to hash and serve content
/// Route: /n/:pubkey/:treename or /n/:pubkey/:treename/*path
pub async fn resolve_and_serve(
    State(state): State<AppState>,
    Path(params): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let (pubkey, treename) = params;
    let key = format!("{}/{}", pubkey, treename);

    let resolver = match NostrRootResolver::new(resolver_config()).await {
        Ok(r) => r,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(json!({
                    "error": format!("Failed to create resolver: {}", e),
                    "key": key
                }).to_string()))
                .unwrap()
                .into_response();
        }
    };

    // Use resolve_wait with timeout - waits for key to appear
    match tokio::time::timeout(HTTP_RESOLVER_TIMEOUT, resolver.resolve_wait(&key)).await {
        Ok(Ok(cid)) => {
            let hash_hex = to_hex(&cid.hash);
            let _ = resolver.stop().await;
            serve_content_internal(&state, &hash_hex, headers).await
        }
        Ok(Err(e)) => {
            let _ = resolver.stop().await;
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(json!({
                    "error": e.to_string(),
                    "key": key
                }).to_string()))
                .unwrap()
                .into_response()
        }
        Err(_) => {
            let _ = resolver.stop().await;
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(json!({
                    "error": "Resolution timeout",
                    "key": key
                }).to_string()))
                .unwrap()
                .into_response()
        }
    }
}

/// API endpoint to resolve npub/treename to hash (returns JSON)
pub async fn resolve_to_hash(
    Path(params): Path<(String, String)>,
) -> impl IntoResponse {
    let (pubkey, treename) = params;
    let key = format!("{}/{}", pubkey, treename);

    let resolver = match NostrRootResolver::new(resolver_config()).await {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({
                "error": format!("Failed to create resolver: {}", e),
                "key": key
            }));
        }
    };

    let result = match tokio::time::timeout(HTTP_RESOLVER_TIMEOUT, resolver.resolve_wait(&key)).await {
        Ok(Ok(cid)) => {
            Json(json!({
                "key": key,
                "hash": to_hex(&cid.hash),
                "cid": cid.to_string()
            }))
        }
        Ok(Err(e)) => {
            Json(json!({
                "error": e.to_string(),
                "key": key
            }))
        }
        Err(_) => {
            Json(json!({
                "error": "Resolution timeout",
                "key": key
            }))
        }
    };

    let _ = resolver.stop().await;
    result
}

/// List all trees for a pubkey
pub async fn list_trees(
    Path(pubkey): Path<String>,
) -> impl IntoResponse {
    let resolver = match NostrRootResolver::new(resolver_config()).await {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({
                "error": format!("Failed to create resolver: {}", e),
                "pubkey": pubkey
            }));
        }
    };

    // list() uses the configured timeout internally
    let result = match resolver.list(&pubkey).await {
        Ok(entries) => {
            Json(json!({
                "pubkey": pubkey,
                "trees": entries.iter().map(|e| json!({
                    "name": e.key.split('/').last().unwrap_or(&e.key),
                    "hash": to_hex(&e.cid.hash),
                    "cid": e.cid.to_string()
                })).collect::<Vec<_>>()
            }))
        }
        Err(e) => {
            Json(json!({
                "error": e.to_string(),
                "pubkey": pubkey
            }))
        }
    };

    let _ = resolver.stop().await;
    result
}
