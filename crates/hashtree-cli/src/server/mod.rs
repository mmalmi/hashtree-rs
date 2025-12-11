mod auth;
pub mod blossom;
pub mod data_ws;
mod git;
mod handlers;
mod mime;
pub mod stun;
mod ui;

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{any, get, post, put},
    Router,
};
use crate::storage::HashtreeStore;
use hashtree_git::GitStorage;
use nostrdb::Ndb;
use hashtree_relay::{ws_handler, RelayState};
use std::sync::Arc;

pub use auth::{AppState, AuthCredentials};

pub struct HashtreeServer {
    state: AppState,
    relay_state: Option<RelayState>,
    git_storage: Option<Arc<GitStorage>>,
    local_pubkey: Option<String>,
    addr: String,
    enable_data_ws: bool,
}

impl HashtreeServer {
    pub fn new(store: Arc<HashtreeStore>, addr: String) -> Self {
        // Create shared peer registry for HTTP handlers and WebSocket
        let peers = Arc::new(data_ws::PeerRegistry::new());

        Self {
            state: AppState {
                store,
                auth: None,
                ndb_query: None,
                peers: Some(peers),
            },
            relay_state: None,
            git_storage: None,
            local_pubkey: None,
            addr,
            enable_data_ws: true, // Enabled by default
        }
    }

    /// Enable or disable the /ws/data WebSocket endpoint for P2P data exchange
    pub fn with_data_ws(mut self, enabled: bool) -> Self {
        self.enable_data_ws = enabled;
        self
    }

    /// Enable git smart HTTP protocol
    pub fn with_git(mut self, storage: Arc<GitStorage>, local_pubkey: String) -> Self {
        self.git_storage = Some(storage);
        self.local_pubkey = Some(local_pubkey);
        self
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.state.auth = Some(AuthCredentials { username, password });
        self
    }

    pub fn with_ndb(mut self, ndb: Ndb) -> Self {
        self.relay_state = Some(RelayState {
            ndb: Arc::new(ndb),
            max_write_distance: None, // No restriction by default
        });
        self
    }

    /// Set maximum follow distance for write access to the relay
    /// distance 0 = only root user, 1 = root + direct follows, etc.
    /// None = no restriction (anyone can write)
    pub fn with_max_write_distance(mut self, max_distance: Option<u32>) -> Self {
        if let Some(ref mut state) = self.relay_state {
            state.max_write_distance = max_distance;
        }
        self
    }

    pub fn with_ndb_query(mut self, query: hashtree_relay::NdbQuerySender) -> Self {
        self.state.ndb_query = Some(query);
        self
    }

    pub async fn run(self) -> Result<()> {
        // Public endpoints (no auth required)
        // Note: /:id serves both CID and blossom SHA256 hash lookups
        // The handler differentiates based on hash format (64 char hex = blossom)
        let mut public_routes = Router::new()
            .route("/", get(handlers::serve_root))
            // Nostr resolver endpoints - resolve npub/treename to content
            .route("/n/:pubkey/:treename", get(handlers::resolve_and_serve))
            // Direct npub/nhash routes (cleaner URLs without /n/ prefix)
            .route("/npub1:rest", get(handlers::serve_npub))
            .route("/nhash1:rest", get(handlers::serve_nhash))
            // Blossom endpoints (BUD-01, BUD-02)
            .route("/:id", get(handlers::serve_content_or_blob)
                .head(blossom::head_blob)
                .delete(blossom::delete_blob)
                .options(blossom::cors_preflight))
            .route("/upload", put(blossom::upload_blob)
                .options(blossom::cors_preflight))
            .route("/list/:pubkey", get(blossom::list_blobs)
                .options(blossom::cors_preflight))
            // Hashtree API endpoints
            .route("/api/pins", get(handlers::list_pins))
            .route("/api/stats", get(handlers::storage_stats))
            .route("/api/socialgraph", get(handlers::socialgraph_stats))
            // Resolver API endpoints
            .route("/api/resolve/:pubkey/:treename", get(handlers::resolve_to_hash))
            .route("/api/trees/:pubkey", get(handlers::list_trees))
            .with_state(self.state.clone());

        // Add nostr relay WebSocket endpoint if ndb is configured
        if let Some(relay_state) = self.relay_state {
            let relay_routes = Router::new()
                .route("/", any(ws_handler))
                .with_state(relay_state);
            public_routes = public_routes.merge(relay_routes);
        }

        // Add git smart HTTP routes if git storage is configured
        if let Some(git_storage) = self.git_storage {
            let local_pubkey = self.local_pubkey.unwrap_or_default();
            let git_state = git::GitState { storage: git_storage, local_pubkey };
            let git_routes = Router::new()
                .route("/git/:pubkey/:repo/info/refs", get(git::info_refs))
                .route("/git/:pubkey/:repo/git-upload-pack", post(git::upload_pack))
                .route("/git/:pubkey/:repo/git-receive-pack", post(git::receive_pack))
                .route("/api/git/repos", get(git::list_repos))
                .with_state(git_state);
            public_routes = public_routes.merge(git_routes);
        }

        // Add data WebSocket endpoint for P2P file sharing (same protocol as WebRTC)
        // Uses shared peer registry so HTTP handlers can also query peers
        if self.enable_data_ws {
            let peers = self.state.peers.clone().unwrap_or_else(|| Arc::new(data_ws::PeerRegistry::new()));
            let data_ws_state = data_ws::DataWsState::with_peers(self.state.store.clone(), peers);
            let data_ws_routes = Router::new()
                .route("/ws/data", get(data_ws::data_ws_handler))
                .with_state(data_ws_state);
            public_routes = public_routes.merge(data_ws_routes);
        }

        // Protected endpoints (require auth if enabled)
        let protected_routes = Router::new()
            .route("/upload", post(handlers::upload_file))
            .route("/api/pin/:cid", post(handlers::pin_cid))
            .route("/api/unpin/:cid", post(handlers::unpin_cid))
            .route("/api/gc", post(handlers::garbage_collect))
            .layer(middleware::from_fn_with_state(
                self.state.clone(),
                auth::auth_middleware,
            ))
            .with_state(self.state);

        let app = public_routes
            .merge(protected_routes)
            .layer(DefaultBodyLimit::max(10 * 1024 * 1024 * 1024)); // 10GB limit

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        ).await?;

        Ok(())
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::HashtreeStore;
    use tempfile::TempDir;
    use std::path::Path;

    #[tokio::test]
    async fn test_server_serve_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(HashtreeStore::new(temp_dir.path().join("db"))?);

        // Create and upload a test file
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Hello, Hashtree!")?;

        let cid = store.upload_file(&test_file)?;

        // Verify we can get it
        let content = store.get_file(&cid)?;
        assert!(content.is_some());
        assert_eq!(content.unwrap(), b"Hello, Hashtree!");

        Ok(())
    }

    #[tokio::test]
    async fn test_server_list_pins() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let store = Arc::new(HashtreeStore::new(temp_dir.path().join("db"))?);

        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Test")?;

        let cid = store.upload_file(&test_file)?;

        let pins = store.list_pins()?;
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], cid);

        Ok(())
    }
}
