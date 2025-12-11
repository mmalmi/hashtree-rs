use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    middleware::Next,
};
use crate::storage::HashtreeStore;
use crate::server::data_ws::PeerRegistry;
use hashtree_relay::NdbQuerySender;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<HashtreeStore>,
    pub auth: Option<AuthCredentials>,
    pub ndb_query: Option<NdbQuerySender>,
    /// Peer registry for forwarding requests to connected WebSocket/WebRTC peers
    pub peers: Option<Arc<PeerRegistry>>,
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
