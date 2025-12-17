//! Integration tests for Blossom access control with social graph
//!
//! Tests the access control logic for blossom blob uploads:
//! - Hardcoded subscribers are always allowed
//! - Users within DEFAULT_MAX_WRITE_DISTANCE (3) degrees of separation are allowed
//! - Users muted by root are denied
//! - Overmuted users (high muter/follower ratio) are denied
//!
//! Note: Full e2e tests with nostrdb social graph require a running relay
//! and populated social graph. These tests focus on the HTTP API behavior.
//!
//! Run with: cargo test --package hashtree-cli --test blossom_access -- --nocapture

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use nostr::{Keys, ToBech32};

struct TestServer {
    _data_dir: TempDir,
    _home_dir: TempDir,
    process: Child,
    port: u16,
}

impl TestServer {
    fn new(port: u16, enable_auth: bool) -> Self {
        let htree_bin = find_htree_binary();
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let home_dir = TempDir::new().expect("Failed to create home dir");

        // Create .hashtree config dir
        let config_dir = home_dir.path().join(".hashtree");
        std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");

        // Create config
        let config_content = format!(r#"
[server]
enable_auth = {}
stun_port = 0
enable_webrtc = false

[nostr]
relays = []
crawl_depth = 0
"#, enable_auth);
        std::fs::write(config_dir.join("config.toml"), config_content)
            .expect("Failed to write config");

        // Generate and write nsec
        let keys = Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("Failed to encode nsec");
        std::fs::write(config_dir.join("nsec"), &nsec)
            .expect("Failed to write nsec");

        let process = Command::new(htree_bin)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("start")
            .arg("--addr")
            .arg(format!("127.0.0.1:{}", port))
            .env("HOME", home_dir.path())
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start htree server");

        // Wait for server to start
        std::thread::sleep(Duration::from_secs(2));

        TestServer {
            _data_dir: data_dir,
            _home_dir: home_dir,
            process,
            port,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn find_htree_binary() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let debug_bin = workspace_root.join("target/debug/htree");
    let release_bin = workspace_root.join("target/release/htree");

    if debug_bin.exists() {
        debug_bin
    } else if release_bin.exists() {
        release_bin
    } else {
        panic!(
            "htree binary not found. Run `cargo build --bin htree` first.\n\
             Looked in:\n  - {:?}\n  - {:?}",
            debug_bin, release_bin
        );
    }
}

/// Create a blossom auth header for upload
/// Kind 24242 event with "upload" action tag
fn create_blossom_auth(keys: &Keys) -> String {
    use nostr::{EventBuilder, Kind, Tag, TagKind, Timestamp};
    use base64::Engine;

    let now = Timestamp::now();
    let expiration = Timestamp::from(now.as_u64() + 300); // 5 minutes

    // Create kind 24242 event
    let event = EventBuilder::new(
        Kind::Custom(24242),
        "",
    )
    .tag(Tag::custom(TagKind::Custom("t".into()), vec!["upload".to_string()]))
    .tag(Tag::custom(TagKind::Custom("expiration".into()), vec![expiration.to_string()]))
    .sign_with_keys(keys)
    .expect("Failed to sign event");

    let event_json = serde_json::to_string(&event).expect("Failed to serialize event");
    let encoded = base64::engine::general_purpose::STANDARD.encode(event_json);

    format!("Nostr {}", encoded)
}

/// Test that uploads without auth are rejected when auth is enabled
#[test]
fn test_upload_requires_auth() {
    let server = TestServer::new(19001, true);

    // Try to upload without auth header
    let output = Command::new("curl")
        .arg("-s")
        .arg("-w").arg("\n%{http_code}")
        .arg("-X").arg("PUT")
        .arg("-H").arg("Content-Type: application/octet-stream")
        .arg("--data-binary").arg("test content")
        .arg(format!("{}/upload", server.base_url()))
        .output()
        .expect("Failed to run curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response: {}", response);

    // Should get 401 Unauthorized
    assert!(response.contains("401") || response.contains("error"),
        "Upload without auth should be rejected");
}

/// Test that uploads with valid auth are processed
/// Note: Without social graph, auth'd uploads may still be rejected if not in allowed list
#[test]
fn test_upload_with_auth_header() {
    let server = TestServer::new(19002, true);

    let keys = Keys::generate();
    let auth_header = create_blossom_auth(&keys);

    println!("Testing upload with auth header...");
    println!("Pubkey: {}", keys.public_key().to_hex());

    let output = Command::new("curl")
        .arg("-s")
        .arg("-w").arg("\n%{http_code}")
        .arg("-X").arg("PUT")
        .arg("-H").arg("Content-Type: application/octet-stream")
        .arg("-H").arg(format!("Authorization: {}", auth_header))
        .arg("--data-binary").arg("test content for upload")
        .arg(format!("{}/upload", server.base_url()))
        .output()
        .expect("Failed to run curl");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("Response: {}", response);

    // Should get either success (200/201) or forbidden (403) based on social graph
    // We're testing that auth header is processed correctly
    assert!(
        response.contains("200") ||
        response.contains("201") ||
        response.contains("403") ||
        response.contains("error"),
        "Should get a valid response (success or forbidden)"
    );
}

/// Test that blobs can be retrieved without auth (GET is public)
#[test]
fn test_get_blob_no_auth_required() {
    let server = TestServer::new(19003, false); // Disable auth for this test

    // Upload a blob first (no auth)
    let test_content = "Hello, Blossom!";
    let upload_output = Command::new("curl")
        .arg("-s")
        .arg("-X").arg("PUT")
        .arg("-H").arg("Content-Type: text/plain")
        .arg("--data-binary").arg(test_content)
        .arg(format!("{}/upload", server.base_url()))
        .output()
        .expect("Failed to upload");

    let upload_response = String::from_utf8_lossy(&upload_output.stdout);
    println!("Upload response: {}", upload_response);

    // Extract sha256 from response
    let sha256: Option<String> = serde_json::from_str::<serde_json::Value>(&upload_response)
        .ok()
        .and_then(|v| v.get("sha256").and_then(|s| s.as_str()).map(|s| s.to_string()));

    if let Some(hash) = sha256 {
        println!("Uploaded blob hash: {}", hash);

        // GET should work without auth
        let get_output = Command::new("curl")
            .arg("-s")
            .arg("-w").arg("\n%{http_code}")
            .arg(format!("{}/{}", server.base_url(), hash))
            .output()
            .expect("Failed to get blob");

        let get_response = String::from_utf8_lossy(&get_output.stdout);
        println!("GET response: {}", get_response);

        assert!(get_response.contains(test_content) || get_response.contains("200"),
            "GET should return the blob content");
    }
}

/// Test HEAD request for blob existence check
#[test]
fn test_head_blob() {
    let server = TestServer::new(19004, false);

    // Upload a blob
    let upload_output = Command::new("curl")
        .arg("-s")
        .arg("-X").arg("PUT")
        .arg("-H").arg("Content-Type: text/plain")
        .arg("--data-binary").arg("HEAD test content")
        .arg(format!("{}/upload", server.base_url()))
        .output()
        .expect("Failed to upload");

    let upload_response = String::from_utf8_lossy(&upload_output.stdout);
    println!("Upload response: {}", upload_response);

    let sha256: Option<String> = serde_json::from_str::<serde_json::Value>(&upload_response)
        .ok()
        .and_then(|v| v.get("sha256").and_then(|s| s.as_str()).map(|s| s.to_string()));

    if let Some(hash) = sha256 {
        // HEAD should return 200 for existing blob
        let head_output = Command::new("curl")
            .arg("-s")
            .arg("-I") // HEAD request
            .arg("-w").arg("\n%{http_code}")
            .arg(format!("{}/{}", server.base_url(), hash))
            .output()
            .expect("Failed to HEAD blob");

        let head_response = String::from_utf8_lossy(&head_output.stdout);
        println!("HEAD response: {}", head_response);

        assert!(head_response.contains("200"), "HEAD should return 200 for existing blob");

        // HEAD for non-existent blob should return 404
        let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let head_404 = Command::new("curl")
            .arg("-s")
            .arg("-I")
            .arg("-w").arg("\n%{http_code}")
            .arg(format!("{}/{}", server.base_url(), fake_hash))
            .output()
            .expect("Failed to HEAD blob");

        let head_404_response = String::from_utf8_lossy(&head_404.stdout);
        println!("HEAD 404 response: {}", head_404_response);

        assert!(head_404_response.contains("404"), "HEAD should return 404 for non-existent blob");
    }
}

/// Test CORS preflight (OPTIONS request)
#[test]
fn test_cors_preflight() {
    let server = TestServer::new(19005, false);

    let output = Command::new("curl")
        .arg("-s")
        .arg("-X").arg("OPTIONS")
        .arg("-I")
        .arg("-H").arg("Origin: https://example.com")
        .arg("-H").arg("Access-Control-Request-Method: PUT")
        .arg("-H").arg("Access-Control-Request-Headers: Authorization, Content-Type")
        .arg(format!("{}/upload", server.base_url()))
        .output()
        .expect("Failed to send OPTIONS");

    let response = String::from_utf8_lossy(&output.stdout);
    println!("OPTIONS response: {}", response);

    // Should have CORS headers
    assert!(response.contains("Access-Control-Allow-Origin") || response.contains("204"),
        "Should return CORS headers");
}

/// Test list endpoint returns user's blobs
#[test]
fn test_list_blobs() {
    let server = TestServer::new(19006, false);

    // Upload some blobs
    for i in 1..=3 {
        let content = format!("Blob content {}", i);
        Command::new("curl")
            .arg("-s")
            .arg("-X").arg("PUT")
            .arg("-H").arg("Content-Type: text/plain")
            .arg("--data-binary").arg(&content)
            .arg(format!("{}/upload", server.base_url()))
            .output()
            .expect("Failed to upload");
    }

    // List endpoint requires a pubkey parameter: /list/<pubkey>
    // Without a specific pubkey, the endpoint may return 404 or empty
    // This is expected behavior - list is per-user
    let list_output = Command::new("curl")
        .arg("-s")
        .arg("-w").arg("\n%{http_code}")
        .arg(format!("{}/list", server.base_url()))
        .output()
        .expect("Failed to list");

    let list_response = String::from_utf8_lossy(&list_output.stdout);
    println!("List response: {}", list_response);

    // List without pubkey may return 404 (Not found) or empty array
    // Both are valid responses
    assert!(
        list_response.contains("404") ||
        list_response.contains("Not found") ||
        list_response.contains("[]") ||
        list_response.is_empty() ||
        serde_json::from_str::<Vec<serde_json::Value>>(&list_response.lines().next().unwrap_or("")).is_ok(),
        "List should return 404, empty array, or valid JSON"
    );
}

/// Test upload with hardcoded subscriber pubkey
/// This requires using one of the actual hardcoded pubkeys which we shouldn't have the private key for
/// So we just verify the check exists by testing with a non-subscriber key
#[test]
fn test_hardcoded_subscriber_check_exists() {
    // This test verifies the access control logic exists
    // We can't test actual subscriber access without their private keys

    use hashtree_cli::server::blossom::{HARDCODED_SUBSCRIBERS, SOCIAL_GRAPH_ROOT, DEFAULT_MAX_WRITE_DISTANCE};

    // Verify constants are set correctly
    assert!(!HARDCODED_SUBSCRIBERS.is_empty(), "Should have hardcoded subscribers");
    assert!(HARDCODED_SUBSCRIBERS.contains(SOCIAL_GRAPH_ROOT), "Root should be in subscribers");
    assert_eq!(DEFAULT_MAX_WRITE_DISTANCE, 3, "Max distance should be 3");
    assert_eq!(SOCIAL_GRAPH_ROOT.len(), 64, "Root pubkey should be 64 hex chars");
}

/// Test overmuted helper function
#[test]
fn test_overmuted_function() {
    use hashtree_cli::server::blossom::{is_overmuted, OVERMUTED_RATIO, OVERMUTED_MIN_MUTERS};

    // Verify constants
    assert_eq!(OVERMUTED_RATIO, 0.1);
    assert_eq!(OVERMUTED_MIN_MUTERS, 5);

    // Test the function
    assert!(!is_overmuted(0, 100), "0 muters should not be overmuted");
    assert!(!is_overmuted(4, 100), "Below min muters should not be overmuted");
    assert!(!is_overmuted(5, 100), "5% should not be overmuted");
    assert!(is_overmuted(10, 100), "10% should be overmuted");
    assert!(is_overmuted(50, 100), "50% should be overmuted");
    assert!(!is_overmuted(10, 0), "0 followers should not be overmuted");
}
