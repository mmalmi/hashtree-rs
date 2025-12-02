//! Inbound relay server - accepting connections as a relay (NIP-01)

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use nostrdb::{Filter, FilterBuilder, Ndb, Transaction};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Nostr relay state
#[derive(Clone)]
pub struct RelayState {
    pub ndb: Arc<Ndb>,
    /// Maximum follow distance allowed for write access (None = no restriction)
    pub max_write_distance: Option<u32>,
}

// Note: We parse messages manually as JSON arrays rather than using typed structs
// since NIP-01 uses heterogeneous arrays like ["EVENT", {...}] and ["REQ", "sub1", {...}, {...}]

/// Relay message types (NIP-01)
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RelayMessage {
    Event((&'static str, String, serde_json::Value)),
    Eose((&'static str, String)),
    Ok((&'static str, String, bool, String)),
    Notice((&'static str, String)),
}

impl RelayMessage {
    pub fn event(sub_id: String, event: serde_json::Value) -> Self {
        RelayMessage::Event(("EVENT", sub_id, event))
    }

    pub fn eose(sub_id: String) -> Self {
        RelayMessage::Eose(("EOSE", sub_id))
    }

    pub fn ok(event_id: String, accepted: bool, message: String) -> Self {
        RelayMessage::Ok(("OK", event_id, accepted, message))
    }

    pub fn notice(message: String) -> Self {
        RelayMessage::Notice(("NOTICE", message))
    }
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Handle a WebSocket connection
async fn handle_socket(socket: WebSocket, state: RelayState) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Spawn task to forward messages to client
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    // Track subscriptions for this connection (store JSON filters for potential future use)
    let mut subscriptions: HashMap<String, Vec<serde_json::Value>> = HashMap::new();

    info!("New relay connection");

    // Process incoming messages
    while let Some(result) = receiver.next().await {
        let msg = match result {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => {
                debug!("WebSocket error: {}", e);
                break;
            }
        };

        trace!("Received: {}", msg);

        // Parse JSON array
        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&msg);
        let arr = match parsed {
            Ok(arr) if !arr.is_empty() => arr,
            _ => {
                let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                    "Invalid message format".to_string()
                )).unwrap()).await;
                continue;
            }
        };

        let cmd = arr[0].as_str().unwrap_or("");

        match cmd {
            "EVENT" => {
                if arr.len() < 2 {
                    let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                        "EVENT requires an event object".to_string()
                    )).unwrap()).await;
                    continue;
                }

                let event = &arr[1];
                let event_id = event["id"].as_str().unwrap_or("").to_string();
                let pubkey_hex = event["pubkey"].as_str().unwrap_or("");

                // Check social graph distance if restriction is enabled
                if let Some(max_distance) = state.max_write_distance {
                    let mut pubkey_bytes = [0u8; 32];
                    let allowed = if let Ok(bytes) = hex::decode(pubkey_hex) {
                        if bytes.len() == 32 {
                            pubkey_bytes.copy_from_slice(&bytes);
                            // Check follow distance (uses single transaction)
                            if let Ok(txn) = Transaction::new(&state.ndb) {
                                let distance = nostrdb::socialgraph::get_follow_distance(&txn, &state.ndb, &pubkey_bytes);
                                // distance 1000 means not in social graph
                                distance <= max_distance
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if !allowed {
                        debug!("Rejected event from {} - not in social graph (max distance: {})", pubkey_hex, max_distance);
                        let _ = tx.send(serde_json::to_string(&RelayMessage::ok(
                            event_id,
                            false,
                            format!("restricted: author not in social graph (max distance: {})", max_distance)
                        )).unwrap()).await;
                        continue;
                    }
                }

                // Process event into nostrdb
                let event_json = serde_json::to_string(event).unwrap_or_default();
                match state.ndb.process_event(&event_json) {
                    Ok(_) => {
                        debug!("Accepted event: {}", event_id);
                        let _ = tx.send(serde_json::to_string(&RelayMessage::ok(
                            event_id,
                            true,
                            "".to_string()
                        )).unwrap()).await;
                    }
                    Err(e) => {
                        warn!("Rejected event {}: {}", event_id, e);
                        let _ = tx.send(serde_json::to_string(&RelayMessage::ok(
                            event_id,
                            false,
                            format!("error: {}", e)
                        )).unwrap()).await;
                    }
                }
            }

            "REQ" => {
                if arr.len() < 3 {
                    let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                        "REQ requires subscription_id and at least one filter".to_string()
                    )).unwrap()).await;
                    continue;
                }

                let sub_id = arr[1].as_str().unwrap_or("").to_string();
                if sub_id.is_empty() {
                    let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                        "Invalid subscription ID".to_string()
                    )).unwrap()).await;
                    continue;
                }

                // Parse filters as JSON (we'll rebuild them for each query)
                let filter_jsons: Vec<serde_json::Value> = arr[2..].to_vec();

                if filter_jsons.is_empty() {
                    let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                        "No valid filters".to_string()
                    )).unwrap()).await;
                    continue;
                }

                debug!("REQ {} with {} filters", sub_id, filter_jsons.len());

                // Query nostrdb and collect results (no await in this block)
                let events: Vec<String> = {
                    let mut results = Vec::new();
                    if let Ok(txn) = Transaction::new(&state.ndb) {
                        for filter_json in &filter_jsons {
                            if let Some(filter) = parse_filter(filter_json) {
                                if let Ok(query_results) = state.ndb.query(&txn, &[filter], 500) {
                                    for result in query_results {
                                        if let Ok(note) = state.ndb.get_note_by_key(&txn, result.note_key) {
                                            if let Ok(json) = note.json() {
                                                results.push(json);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    results
                };

                // Now send events (with await)
                for event_json in events {
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&event_json) {
                        let msg = serde_json::to_string(&RelayMessage::event(
                            sub_id.clone(),
                            event
                        )).unwrap();
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                }

                // Send EOSE
                let _ = tx.send(serde_json::to_string(&RelayMessage::eose(sub_id.clone())).unwrap()).await;

                // Store subscription for future events (store JSON filters)
                // Note: We don't track subscriptions for live updates yet
                let _ = subscriptions.insert(sub_id, filter_jsons);
            }

            "CLOSE" => {
                if arr.len() < 2 {
                    continue;
                }
                let sub_id = arr[1].as_str().unwrap_or("").to_string();
                subscriptions.remove(&sub_id);
                debug!("Closed subscription: {}", sub_id);
            }

            _ => {
                let _ = tx.send(serde_json::to_string(&RelayMessage::notice(
                    format!("Unknown command: {}", cmd)
                )).unwrap()).await;
            }
        }
    }

    info!("Relay connection closed");
    send_task.abort();
}

/// Parse a JSON filter object into nostrdb Filter
fn parse_filter(value: &serde_json::Value) -> Option<Filter> {
    let obj = value.as_object()?;

    let mut builder = FilterBuilder::new();

    // ids
    if let Some(ids) = obj.get("ids").and_then(|v| v.as_array()) {
        let id_bytes: Vec<[u8; 32]> = ids
            .iter()
            .filter_map(|id| {
                let hex = id.as_str()?;
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();
        if !id_bytes.is_empty() {
            builder = builder.ids(id_bytes.iter());
        }
    }

    // authors
    if let Some(authors) = obj.get("authors").and_then(|v| v.as_array()) {
        let author_bytes: Vec<[u8; 32]> = authors
            .iter()
            .filter_map(|author| {
                let hex = author.as_str()?;
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();
        if !author_bytes.is_empty() {
            builder = builder.authors(author_bytes.iter());
        }
    }

    // kinds
    if let Some(kinds) = obj.get("kinds").and_then(|v| v.as_array()) {
        let kind_values: Vec<u64> = kinds
            .iter()
            .filter_map(|k| k.as_u64())
            .collect();
        if !kind_values.is_empty() {
            builder = builder.kinds(kind_values);
        }
    }

    // since
    if let Some(since) = obj.get("since").and_then(|v| v.as_u64()) {
        builder = builder.since(since);
    }

    // until
    if let Some(until) = obj.get("until").and_then(|v| v.as_u64()) {
        builder = builder.until(until);
    }

    // limit
    if let Some(limit) = obj.get("limit").and_then(|v| v.as_u64()) {
        builder = builder.limit(limit);
    }

    // #e tags
    if let Some(e_tags) = obj.get("#e").and_then(|v| v.as_array()) {
        for t in e_tags {
            if let Some(hex) = t.as_str() {
                if let Ok(bytes) = hex::decode(hex) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        builder = builder.event(&arr);
                    }
                }
            }
        }
    }

    // #p tags
    if let Some(p_tags) = obj.get("#p").and_then(|v| v.as_array()) {
        let tag_bytes: Vec<[u8; 32]> = p_tags
            .iter()
            .filter_map(|t| {
                let hex = t.as_str()?;
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();
        if !tag_bytes.is_empty() {
            builder = builder.pubkey(tag_bytes.iter());
        }
    }

    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use nostrdb::Config;
    use tempfile::TempDir;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    fn init_test_ndb(path: std::path::PathBuf) -> Ndb {
        std::fs::create_dir_all(&path).unwrap();
        let config = Config::new().set_ingester_threads(1);
        Ndb::new(path.to_str().unwrap(), &config).unwrap()
    }

    async fn setup_test_server() -> (String, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        // Find available port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let relay_state = RelayState {
            ndb: Arc::new(ndb),
            max_write_distance: None, // No restriction for tests
        };

        let app = axum::Router::new()
            .route("/", axum::routing::any(ws_handler))
            .with_state(relay_state);

        let addr_str = addr.to_string();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        (addr_str, temp_dir)
    }

    fn create_test_event() -> (serde_json::Value, String) {
        use nostr::{EventBuilder, Keys, Kind};

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "Test note from hashtree relay test")
            .sign_with_keys(&keys)
            .unwrap();

        let json = nostr::JsonUtil::as_json(&event);
        let event_value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let event_id = event.id.to_hex();

        (event_value, event_id)
    }

    #[tokio::test]
    async fn test_relay_event_and_req() {
        let (addr, _temp_dir) = setup_test_server().await;

        // Connect to relay
        let url = format!("ws://{}", addr);
        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Create and publish an event
        let (event, event_id) = create_test_event();
        let event_msg = serde_json::json!(["EVENT", event]);
        write.send(Message::Text(event_msg.to_string())).await.unwrap();

        // Wait for OK response
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            read.next()
        ).await.expect("Timeout waiting for OK").unwrap().unwrap();

        let ok_msg: Vec<serde_json::Value> = serde_json::from_str(
            response.to_text().unwrap()
        ).unwrap();
        assert_eq!(ok_msg[0], "OK");
        assert_eq!(ok_msg[1], event_id);
        assert_eq!(ok_msg[2], true); // accepted

        // Small delay for nostrdb to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Now query for the event
        let req_msg = serde_json::json!(["REQ", "sub1", {"kinds": [1], "limit": 10}]);
        write.send(Message::Text(req_msg.to_string())).await.unwrap();

        // Collect responses until EOSE
        let mut found_event = false;
        loop {
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                read.next()
            ).await.expect("Timeout waiting for response").unwrap().unwrap();

            let msg: Vec<serde_json::Value> = serde_json::from_str(
                response.to_text().unwrap()
            ).unwrap();

            match msg[0].as_str().unwrap() {
                "EVENT" => {
                    assert_eq!(msg[1], "sub1");
                    if msg[2]["id"] == event_id {
                        found_event = true;
                    }
                }
                "EOSE" => {
                    assert_eq!(msg[1], "sub1");
                    break;
                }
                _ => panic!("Unexpected message: {:?}", msg),
            }
        }

        assert!(found_event, "Published event not found in REQ response");
    }

    #[tokio::test]
    async fn test_relay_close_subscription() {
        let (addr, _temp_dir) = setup_test_server().await;

        let url = format!("ws://{}", addr);
        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Create subscription
        let req_msg = serde_json::json!(["REQ", "sub1", {"kinds": [1], "limit": 10}]);
        write.send(Message::Text(req_msg.to_string())).await.unwrap();

        // Wait for EOSE
        loop {
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                read.next()
            ).await.expect("Timeout").unwrap().unwrap();

            let msg: Vec<serde_json::Value> = serde_json::from_str(
                response.to_text().unwrap()
            ).unwrap();

            if msg[0] == "EOSE" {
                break;
            }
        }

        // Close subscription
        let close_msg = serde_json::json!(["CLOSE", "sub1"]);
        write.send(Message::Text(close_msg.to_string())).await.unwrap();

        // Should be able to send more messages without error
        let req_msg2 = serde_json::json!(["REQ", "sub2", {"kinds": [0], "limit": 5}]);
        write.send(Message::Text(req_msg2.to_string())).await.unwrap();

        // Wait for EOSE on new subscription
        loop {
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                read.next()
            ).await.expect("Timeout").unwrap().unwrap();

            let msg: Vec<serde_json::Value> = serde_json::from_str(
                response.to_text().unwrap()
            ).unwrap();

            if msg[0] == "EOSE" && msg[1] == "sub2" {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_relay_invalid_message() {
        let (addr, _temp_dir) = setup_test_server().await;

        let url = format!("ws://{}", addr);
        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Send invalid message
        write.send(Message::Text("not valid json".to_string())).await.unwrap();

        // Should get NOTICE
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            read.next()
        ).await.expect("Timeout").unwrap().unwrap();

        let msg: Vec<serde_json::Value> = serde_json::from_str(
            response.to_text().unwrap()
        ).unwrap();
        assert_eq!(msg[0], "NOTICE");
    }

    #[tokio::test]
    async fn test_relay_filter_by_author() {
        let (addr, _temp_dir) = setup_test_server().await;

        let url = format!("ws://{}", addr);
        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Publish event
        let (event, _event_id) = create_test_event();
        let author_pubkey = event["pubkey"].as_str().unwrap().to_string();

        let event_msg = serde_json::json!(["EVENT", event]);
        write.send(Message::Text(event_msg.to_string())).await.unwrap();

        // Wait for OK
        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            read.next()
        ).await.expect("Timeout").unwrap().unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Query by author
        let req_msg = serde_json::json!(["REQ", "sub1", {"authors": [author_pubkey], "limit": 10}]);
        write.send(Message::Text(req_msg.to_string())).await.unwrap();

        let mut found = false;
        loop {
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                read.next()
            ).await.expect("Timeout").unwrap().unwrap();

            let msg: Vec<serde_json::Value> = serde_json::from_str(
                response.to_text().unwrap()
            ).unwrap();

            match msg[0].as_str().unwrap() {
                "EVENT" => {
                    assert_eq!(msg[2]["pubkey"].as_str().unwrap(), author_pubkey);
                    found = true;
                }
                "EOSE" => break,
                _ => {}
            }
        }

        assert!(found, "Event not found when filtering by author");

        // Query by different author (should find nothing)
        let fake_author = "0".repeat(64);
        let req_msg2 = serde_json::json!(["REQ", "sub2", {"authors": [fake_author], "limit": 10}]);
        write.send(Message::Text(req_msg2.to_string())).await.unwrap();

        let mut found_fake = false;
        loop {
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(2),
                read.next()
            ).await.expect("Timeout").unwrap().unwrap();

            let msg: Vec<serde_json::Value> = serde_json::from_str(
                response.to_text().unwrap()
            ).unwrap();

            match msg[0].as_str().unwrap() {
                "EVENT" => found_fake = true,
                "EOSE" => break,
                _ => {}
            }
        }

        assert!(!found_fake, "Should not find events for non-existent author");
    }

    #[tokio::test]
    async fn test_relay_social_graph_write_restriction() {
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        // Set a root pubkey for the social graph
        let root_pubkey = [1u8; 32];
        nostrdb::socialgraph::set_root(&ndb, &root_pubkey);

        // Find available port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        // Create relay with max_write_distance = 0 (only root can write)
        let relay_state = RelayState {
            ndb: Arc::new(ndb),
            max_write_distance: Some(0),
        };

        let app = axum::Router::new()
            .route("/", axum::routing::any(ws_handler))
            .with_state(relay_state);

        let addr_str = addr.to_string();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Connect to relay
        let url = format!("ws://{}", addr_str);
        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Try to publish event from random user (not in social graph)
        let (event, event_id) = create_test_event();
        let event_msg = serde_json::json!(["EVENT", event]);
        write.send(Message::Text(event_msg.to_string())).await.unwrap();

        // Should get OK with false (rejected)
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            read.next()
        ).await.expect("Timeout waiting for OK").unwrap().unwrap();

        let ok_msg: Vec<serde_json::Value> = serde_json::from_str(
            response.to_text().unwrap()
        ).unwrap();
        assert_eq!(ok_msg[0], "OK");
        assert_eq!(ok_msg[1], event_id);
        assert_eq!(ok_msg[2], false, "Event should be rejected - author not in social graph");
        assert!(ok_msg[3].as_str().unwrap().contains("restricted"), "Should mention restriction");
    }
}
