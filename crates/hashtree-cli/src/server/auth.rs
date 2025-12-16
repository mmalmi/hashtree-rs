use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    middleware::Next,
};
use crate::storage::HashtreeStore;
use crate::webrtc::WebRTCState;
use hashtree_relay::NdbQuerySender;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<HashtreeStore>,
    pub auth: Option<AuthCredentials>,
    pub ndb_query: Option<NdbQuerySender>,
    /// WebRTC peer state for forwarding requests to connected P2P peers
    pub webrtc_peers: Option<Arc<WebRTCState>>,
    /// Maximum upload size in bytes for Blossom uploads (default: 5 MB)
    pub max_upload_bytes: usize,
    /// Allow anyone with valid Nostr auth to write (default: true)
    /// When false, only social graph members can write
    pub public_writes: bool,
}

#[derive(Clone)]
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
}

/// Auth middleware - validates HTTP Basic Auth
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // If auth is not enabled, allow request
    let Some(auth) = &state.auth else {
        return Ok(next.run(request).await);
    };

    // Check Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let authorized = if let Some(header_value) = auth_header {
        if let Some(credentials) = header_value.strip_prefix("Basic ") {
            use base64::Engine;
            let engine = base64::engine::general_purpose::STANDARD;
            if let Ok(decoded) = engine.decode(credentials) {
                if let Ok(decoded_str) = String::from_utf8(decoded) {
                    let expected = format!("{}:{}", auth.username, auth.password);
                    decoded_str == expected
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if authorized {
        Ok(next.run(request).await)
    } else {
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"hashtree\"")
            .body(Body::from("Unauthorized"))
            .unwrap())
    }
}
