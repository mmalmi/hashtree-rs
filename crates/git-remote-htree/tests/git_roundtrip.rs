//! Integration test: Git push and clone via htree://
//!
//! This test verifies the full git remote helper workflow:
//! 1. Create a test git repository with some files
//! 2. Generate an identity (uses htree://self which auto-generates keys)
//! 3. Push via `git push htree://self/<repo>`
//! 4. Clone to new directory via `git clone htree://self/<repo>`
//! 5. Verify files match
//!
//! By default, tests use local blossom + nostr servers for isolation.
//! Set USE_PRODUCTION_SERVERS=1 to test against real infrastructure.
//!
//! Run with: cargo test --package git-remote-htree --test git_roundtrip -- --nocapture

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use nostr::ToBech32;

/// Minimal in-memory nostr relay for testing
mod test_relay {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_tungstenite::{accept_async, tungstenite::Message};
    use futures::{SinkExt, StreamExt};

    pub struct TestRelay {
        #[allow(dead_code)]
        port: u16,
        #[allow(dead_code)]
        events: Arc<Mutex<HashMap<String, serde_json::Value>>>,
        shutdown: tokio::sync::broadcast::Sender<()>,
    }

    impl TestRelay {
        pub fn new(port: u16) -> Self {
            let events = Arc::new(Mutex::new(HashMap::new()));
            let (shutdown, _) = tokio::sync::broadcast::channel(1);

            let relay = TestRelay {
                port,
                events: events.clone(),
                shutdown: shutdown.clone(),
            };

            // Start relay in background
            let events_clone = events.clone();
            let mut shutdown_rx = shutdown.subscribe();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async move {
                    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
                    listener.set_nonblocking(true).unwrap();
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();

                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => break,
                            result = listener.accept() => {
                                if let Ok((stream, _)) = result {
                                    let events = events_clone.clone();
                                    tokio::spawn(handle_connection(stream, events));
                                }
                            }
                        }
                    }
                });
            });

            // Wait for relay to start
            std::thread::sleep(std::time::Duration::from_millis(100));
            relay
        }

        pub fn url(&self) -> String {
            format!("ws://127.0.0.1:{}", self.port)
        }
    }

    impl Drop for TestRelay {
        fn drop(&mut self) {
            let _ = self.shutdown.send(());
            // Give time for cleanup
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    async fn handle_connection(stream: TcpStream, events: Arc<Mutex<HashMap<String, serde_json::Value>>>) {
        let ws_stream = match accept_async(stream).await {
            Ok(s) => s,
            Err(_) => return,
        };

        let (mut write, mut read) = ws_stream.split();

        while let Some(msg) = read.next().await {
            let msg = match msg {
                Ok(Message::Text(t)) => t,
                Ok(Message::Close(_)) => break,
                _ => continue,
            };

            // Parse nostr message: ["EVENT", event] or ["REQ", sub_id, filter...]
            let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&msg);
            let parsed = match parsed {
                Ok(p) => p,
                Err(_) => continue,
            };

            if parsed.is_empty() {
                continue;
            }

            let msg_type = parsed[0].as_str().unwrap_or("");

            match msg_type {
                "EVENT" => {
                    if parsed.len() >= 2 {
                        let event = &parsed[1];
                        if let Some(id) = event.get("id").and_then(|v| v.as_str()) {
                            events.lock().unwrap().insert(id.to_string(), event.clone());
                            // Send OK response
                            let ok_msg = serde_json::json!(["OK", id, true, ""]);
                            let _ = write.send(Message::Text(ok_msg.to_string())).await;
                        }
                    }
                }
                "REQ" => {
                    if parsed.len() >= 3 {
                        let sub_id = parsed[1].as_str().unwrap_or("sub").to_string();
                        let filter = &parsed[2];

                        // Simple filter matching
                        let kind = filter.get("kinds").and_then(|k| k.as_array()).and_then(|a| a.first()).and_then(|v| v.as_u64());
                        let author = filter.get("authors").and_then(|a| a.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).map(|s| s.to_string());
                        let d_tag = filter.get("#d").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).map(|s| s.to_string());

                        // Collect matching events while holding lock, then release before await
                        let matching_events: Vec<serde_json::Value> = {
                            let events_lock = events.lock().unwrap();
                            events_lock.values().filter(|event| {
                                let mut matches = true;

                                if let Some(k) = kind {
                                    if event.get("kind").and_then(|v| v.as_u64()) != Some(k) {
                                        matches = false;
                                    }
                                }

                                if let Some(ref a) = author {
                                    if event.get("pubkey").and_then(|v| v.as_str()) != Some(a.as_str()) {
                                        matches = false;
                                    }
                                }

                                if let Some(ref d) = d_tag {
                                    let has_d_tag = event.get("tags")
                                        .and_then(|t| t.as_array())
                                        .map(|tags| {
                                            tags.iter().any(|tag| {
                                                tag.as_array().map(|arr| {
                                                    arr.len() >= 2 &&
                                                    arr[0].as_str() == Some("d") &&
                                                    arr[1].as_str() == Some(d.as_str())
                                                }).unwrap_or(false)
                                            })
                                        })
                                        .unwrap_or(false);
                                    if !has_d_tag {
                                        matches = false;
                                    }
                                }

                                matches
                            }).cloned().collect()
                        };

                        // Now send events without holding lock
                        for event in matching_events {
                            let event_msg = serde_json::json!(["EVENT", &sub_id, event]);
                            let _ = write.send(Message::Text(event_msg.to_string())).await;
                        }

                        // Send EOSE
                        let eose = serde_json::json!(["EOSE", &sub_id]);
                        let _ = write.send(Message::Text(eose.to_string())).await;
                    }
                }
                "CLOSE" => {
                    // Subscription closed, ignore
                }
                _ => {}
            }
        }
    }
}

/// Local blossom server for testing
struct TestServer {
    _data_dir: TempDir,
    _home_dir: TempDir,
    process: Child,
    port: u16,
}

impl TestServer {
    fn new(port: u16) -> Option<Self> {
        let htree_bin = find_htree_binary()?;
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let home_dir = TempDir::new().expect("Failed to create home dir");

        // Create .hashtree config dir for the server
        let config_dir = home_dir.path().join(".hashtree");
        std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");

        // Server config - no auth for testing
        let config_content = r#"
[server]
enable_auth = false
stun_port = 0
enable_webrtc = false
public_writes = true

[nostr]
relays = []
"#;
        std::fs::write(config_dir.join("config.toml"), config_content)
            .expect("Failed to write config");

        // Generate keys for server
        let keys = nostr::Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("Failed to encode nsec");
        std::fs::write(config_dir.join("keys"), &nsec)
            .expect("Failed to write keys");

        let process = Command::new(&htree_bin)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("start")
            .arg("--addr")
            .arg(format!("127.0.0.1:{}", port))
            .env("HOME", home_dir.path())
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start htree server");

        // Wait for server to start
        std::thread::sleep(Duration::from_secs(2));

        Some(TestServer {
            _data_dir: data_dir,
            _home_dir: home_dir,
            process,
            port,
        })
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

fn find_htree_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()?
        .parent()?
        .to_path_buf();

    let debug_bin = workspace_root.join("target/debug/htree");
    let release_bin = workspace_root.join("target/release/htree");

    if release_bin.exists() {
        Some(release_bin)
    } else if debug_bin.exists() {
        Some(debug_bin)
    } else {
        None
    }
}

struct TestEnv {
    _data_dir: TempDir,
    home_dir: PathBuf,
    npub: String,
}

impl TestEnv {
    fn new(blossom_server: Option<&str>, nostr_relay: Option<&str>) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let home_dir = data_dir.path().to_path_buf();

        // Create .hashtree config dir
        let config_dir = home_dir.join(".hashtree");
        std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");

        // Build config
        let relays = match nostr_relay {
            Some(url) => format!(r#"relays = ["{}"]"#, url),
            None => r#"relays = ["wss://temp.iris.to", "wss://relay.damus.io"]"#.to_string(),
        };

        let blossom = match blossom_server {
            Some(url) => format!(r#"
[blossom]
read_servers = ["{url}"]
write_servers = ["{url}"]
"#),
            None => String::new(),
        };

        let config_content = format!(r#"
[server]
enable_auth = false
stun_port = 0

[nostr]
{relays}
crawl_depth = 0

{blossom}
"#);

        std::fs::write(config_dir.join("config.toml"), config_content)
            .expect("Failed to write config");

        // Generate a test key for "self" identity
        let keys = nostr::Keys::generate();
        let nsec = keys.secret_key().to_bech32().expect("Failed to encode nsec");
        let npub = keys.public_key().to_bech32().expect("Failed to encode npub");
        let key_line = format!("{} self\n", nsec);
        std::fs::write(config_dir.join("keys"), &key_line)
            .expect("Failed to write keys");
        println!("Generated test key: {} (petname: self)", &nsec[..20]);

        TestEnv {
            _data_dir: data_dir,
            home_dir,
            npub,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        let config_dir = self.home_dir.join(".hashtree");
        vec![
            (
                "HOME".to_string(),
                self.home_dir.to_string_lossy().to_string(),
            ),
            (
                "HTREE_CONFIG_DIR".to_string(),
                config_dir.to_string_lossy().to_string(),
            ),
            (
                "PATH".to_string(),
                format!(
                    "{}:{}",
                    find_git_remote_htree_dir()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            ),
        ]
    }
}

fn find_git_remote_htree_dir() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()?
        .parent()?
        .to_path_buf();

    let release_dir = workspace_root.join("target/release");
    let debug_dir = workspace_root.join("target/debug");

    if release_dir.join("git-remote-htree").exists() {
        Some(release_dir)
    } else if debug_dir.join("git-remote-htree").exists() {
        Some(debug_dir)
    } else {
        None
    }
}

fn create_test_repo() -> TempDir {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let path = dir.path();

    // Init git repo
    let status = Command::new("git")
        .args(["init"])
        .current_dir(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("Failed to run git init");
    assert!(status.success(), "git init failed");

    // Configure git
    Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(path)
        .status()
        .expect("Failed to configure git");
    Command::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(path)
        .status()
        .expect("Failed to configure git");

    // Create test files
    std::fs::write(path.join("README.md"), "# Test Repository\n\nThis is a test.\n").unwrap();
    std::fs::write(path.join("hello.txt"), "Hello, World!\n").unwrap();
    std::fs::create_dir_all(path.join("src")).unwrap();
    std::fs::write(
        path.join("src/main.rs"),
        r#"fn main() {
    println!("Hello from test repo!");
}
"#,
    )
    .unwrap();

    // Commit
    Command::new("git")
        .args(["add", "-A"])
        .current_dir(path)
        .status()
        .expect("Failed to git add");
    Command::new("git")
        .args(["commit", "-m", "Initial commit"])
        .current_dir(path)
        .stdout(Stdio::null())
        .status()
        .expect("Failed to git commit");

    dir
}

/// Test git push and clone with local servers (no network needed)
#[test]
fn test_git_push_and_clone_local() {
    // Check prerequisites
    if find_git_remote_htree_dir().is_none() {
        println!(
            "SKIP: git-remote-htree binary not found. Run `cargo build -p git-remote-htree` first."
        );
        return;
    }

    // Start local nostr relay
    let relay = test_relay::TestRelay::new(19200);
    println!("Started local nostr relay at: {}", relay.url());

    // Start local blossom server
    let server = match TestServer::new(19201) {
        Some(s) => s,
        None => {
            println!("SKIP: htree binary not found. Run `cargo build --bin htree` first.");
            return;
        }
    };
    println!("Started local blossom server at: {}", server.base_url());

    println!("\n=== Git Push/Clone Roundtrip Test (Local Servers) ===\n");

    // Create test environment pointing to local servers
    let test_env = TestEnv::new(Some(&server.base_url()), Some(&relay.url()));
    println!("Test environment at: {:?}\n", test_env.home_dir);

    // Create test repo
    println!("Creating test repository...");
    let repo = create_test_repo();
    println!("Test repo at: {:?}\n", repo.path());

    // Add htree remote
    let remote_url = "htree://self/test-repo-local";
    println!("Adding remote: {}", remote_url);

    let env_vars: Vec<_> = test_env.env();

    let add_remote = Command::new("git")
        .args(["remote", "add", "htree", remote_url])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to add remote");

    if !add_remote.status.success() {
        panic!(
            "git remote add failed: {}",
            String::from_utf8_lossy(&add_remote.stderr)
        );
    }

    // Push to htree
    println!("\nPushing to htree...");
    let push_start = std::time::Instant::now();

    let push = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to run git push");

    let push_duration = push_start.elapsed();
    println!("Push stderr: {}", String::from_utf8_lossy(&push.stderr));
    println!("Push took: {:?}", push_duration);

    let stderr = String::from_utf8_lossy(&push.stderr);
    let push_worked = stderr.contains("-> master") || stderr.contains("-> main");

    if !push.status.success() && !push_worked {
        panic!("git push failed: {}", stderr);
    }
    println!("Push successful!\n");

    // Clone using the npub
    let npub = &test_env.npub;
    let clone_url = format!("htree://{}/test-repo-local", npub);
    let clone_dir = TempDir::new().expect("Failed to create clone dir");
    let clone_path = clone_dir.path().join("cloned-repo");

    println!("Cloning from {} to {:?}...", clone_url, clone_path);
    let clone_start = std::time::Instant::now();

    let clone = Command::new("git")
        .args(["clone", &clone_url, clone_path.to_str().unwrap()])
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to run git clone");

    let clone_duration = clone_start.elapsed();
    println!("Clone stderr: {}", String::from_utf8_lossy(&clone.stderr));
    println!("Clone took: {:?}", clone_duration);

    if !clone.status.success() {
        panic!("git clone failed: {}", String::from_utf8_lossy(&clone.stderr));
    }
    println!("Clone successful!\n");

    // Verify files match
    println!("Verifying files...");

    let original_readme = std::fs::read_to_string(repo.path().join("README.md")).unwrap();
    let cloned_readme = std::fs::read_to_string(clone_path.join("README.md")).unwrap();
    assert_eq!(original_readme, cloned_readme, "README.md should match");

    let original_hello = std::fs::read_to_string(repo.path().join("hello.txt")).unwrap();
    let cloned_hello = std::fs::read_to_string(clone_path.join("hello.txt")).unwrap();
    assert_eq!(original_hello, cloned_hello, "hello.txt should match");

    let original_main = std::fs::read_to_string(repo.path().join("src/main.rs")).unwrap();
    let cloned_main = std::fs::read_to_string(clone_path.join("src/main.rs")).unwrap();
    assert_eq!(original_main, cloned_main, "src/main.rs should match");

    println!("\n=== SUCCESS: Local git roundtrip test passed! ===");
    println!("Push time: {:?}", push_duration);
    println!("Clone time: {:?}", clone_duration);
}

/// Test diff-based push - second push should upload fewer blobs
#[test]
fn test_diff_based_push() {
    // Check prerequisites
    if find_git_remote_htree_dir().is_none() {
        println!(
            "SKIP: git-remote-htree binary not found. Run `cargo build -p git-remote-htree` first."
        );
        return;
    }

    // Start local servers
    let relay = test_relay::TestRelay::new(19202);
    let server = match TestServer::new(19203) {
        Some(s) => s,
        None => {
            println!("SKIP: htree binary not found. Run `cargo build --bin htree` first.");
            return;
        }
    };

    println!("=== Diff-Based Push Test ===\n");
    println!("Local relay: {}, blossom: {}\n", relay.url(), server.base_url());

    let test_env = TestEnv::new(Some(&server.base_url()), Some(&relay.url()));
    let env_vars: Vec<_> = test_env.env();

    // Create and push initial repo
    let repo = create_test_repo();
    println!("Test repo at: {:?}\n", repo.path());

    let remote_url = "htree://self/diff-test-repo";
    Command::new("git")
        .args(["remote", "add", "htree", remote_url])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to add remote");

    // First push
    println!("=== First push (full upload) ===");
    let push1 = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr1 = String::from_utf8_lossy(&push1.stderr);
    println!("First push stderr:\n{}", stderr1);

    if !push1.status.success() && !stderr1.contains("-> master") {
        panic!("First push failed: {}", stderr1);
    }

    // Make a small change
    println!("\n=== Making small change ===");
    std::fs::write(repo.path().join("small-change.txt"), "Just a small change\n")
        .expect("Failed to write file");

    Command::new("git")
        .args(["add", "small-change.txt"])
        .current_dir(repo.path())
        .output()
        .expect("Failed to git add");

    Command::new("git")
        .args(["commit", "-m", "Add small change"])
        .current_dir(repo.path())
        .stdout(Stdio::null())
        .output()
        .expect("Failed to commit");

    // Second push - should use diff
    println!("\n=== Second push (should use diff) ===");
    let push2 = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr2 = String::from_utf8_lossy(&push2.stderr);
    println!("Second push stderr:\n{}", stderr2);

    if !push2.status.success() && !stderr2.contains("-> master") {
        panic!("Second push failed: {}", stderr2);
    }

    // Verify diff was used
    let used_diff = stderr2.contains("unchanged") || stderr2.contains("Computing diff");
    println!("\nDiff optimization used: {}", used_diff);
    assert!(used_diff, "Second push should use diff optimization");

    // Third push with no changes
    println!("\n=== Third push (no changes) ===");
    let push3 = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr3 = String::from_utf8_lossy(&push3.stderr);
    println!("Third push stderr:\n{}", stderr3);

    // Either detects exact same root hash OR uploads very few blobs
    // Note: The index file contains timestamps which may cause small variations
    let no_changes = stderr3.contains("No changes") || stderr3.contains("same root");
    let minimal_upload = stderr3.contains("unchanged") && {
        // Parse "X new" from output - should be small (< 10)
        stderr3.split_whitespace()
            .zip(stderr3.split_whitespace().skip(1))
            .find(|(_, word)| *word == "new,")
            .and_then(|(num, _)| num.strip_prefix('(').unwrap_or(num).parse::<u32>().ok())
            .map(|n| n < 10)
            .unwrap_or(false)
    };
    println!("No-change optimization used: {} (minimal_upload: {})", no_changes, minimal_upload);
    assert!(no_changes || minimal_upload, "Third push should detect no changes or upload minimal blobs");

    println!("\n=== SUCCESS: Diff-based push test passed! ===");
}

/// Test with production servers (requires network)
#[test]
#[ignore = "requires network - run with: cargo test --test git_roundtrip test_git_push_and_clone_production -- --ignored --nocapture"]
fn test_git_push_and_clone_production() {
    if find_git_remote_htree_dir().is_none() {
        panic!("git-remote-htree binary not found");
    }

    println!("=== Git Push/Clone Roundtrip Test (Production Servers) ===\n");

    let test_env = TestEnv::new(None, None);
    let repo = create_test_repo();
    let env_vars: Vec<_> = test_env.env();

    Command::new("git")
        .args(["remote", "add", "htree", "htree://self/test-repo"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to add remote");

    let push = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr = String::from_utf8_lossy(&push.stderr);
    println!("Push stderr: {}", stderr);

    if !push.status.success() && !stderr.contains("-> master") {
        panic!("git push failed: {}", stderr);
    }

    let npub = &test_env.npub;
    let clone_url = format!("htree://{}/test-repo", npub);
    let clone_dir = TempDir::new().unwrap();
    let clone_path = clone_dir.path().join("cloned");

    let clone = Command::new("git")
        .args(["clone", &clone_url, clone_path.to_str().unwrap()])
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to clone");

    if !clone.status.success() {
        panic!("git clone failed: {}", String::from_utf8_lossy(&clone.stderr));
    }

    assert_eq!(
        std::fs::read_to_string(repo.path().join("README.md")).unwrap(),
        std::fs::read_to_string(clone_path.join("README.md")).unwrap()
    );

    println!("\n=== SUCCESS ===");
}

/// Test diff-based push with production servers
#[test]
#[ignore = "requires network - run with: cargo test --test git_roundtrip test_diff_based_push_production -- --ignored --nocapture"]
fn test_diff_based_push_production() {
    if find_git_remote_htree_dir().is_none() {
        panic!("git-remote-htree binary not found");
    }

    println!("=== Diff-Based Push Test (Production Servers) ===\n");

    let test_env = TestEnv::new(None, None);
    let repo = create_test_repo();
    let env_vars: Vec<_> = test_env.env();

    let remote_url = "htree://self/diff-test-prod";
    Command::new("git")
        .args(["remote", "add", "htree", remote_url])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to add remote");

    // First push
    println!("=== First push (full upload) ===");
    let push1 = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr1 = String::from_utf8_lossy(&push1.stderr);
    println!("{}", stderr1);
    if !push1.status.success() && !stderr1.contains("-> master") {
        panic!("First push failed: {}", stderr1);
    }

    // Make small change
    println!("\n=== Making small change ===");
    std::fs::write(repo.path().join("new-file.txt"), "Small change\n").unwrap();
    Command::new("git").args(["add", "."]).current_dir(repo.path()).output().unwrap();
    Command::new("git").args(["commit", "-m", "Add file"]).current_dir(repo.path())
        .stdout(Stdio::null()).output().unwrap();

    // Second push - should use diff
    println!("\n=== Second push (should use diff) ===");
    let push2 = Command::new("git")
        .args(["push", "htree", "master"])
        .current_dir(repo.path())
        .envs(env_vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .output()
        .expect("Failed to push");

    let stderr2 = String::from_utf8_lossy(&push2.stderr);
    println!("{}", stderr2);
    if !push2.status.success() && !stderr2.contains("-> master") {
        panic!("Second push failed: {}", stderr2);
    }

    let used_diff = stderr2.contains("unchanged") || stderr2.contains("Computing diff");
    println!("\nDiff optimization used: {}", used_diff);
    assert!(used_diff, "Second push should use diff optimization");

    println!("\n=== SUCCESS ===");
}

#[test]
fn test_git_remote_htree_binary_exists() {
    if find_git_remote_htree_dir().is_none() {
        println!(
            "SKIP: git-remote-htree binary not found. Build with: cargo build -p git-remote-htree"
        );
        return;
    }

    let bin_dir = find_git_remote_htree_dir().unwrap();
    let binary = bin_dir.join("git-remote-htree");
    assert!(binary.exists(), "git-remote-htree binary should exist");
}
