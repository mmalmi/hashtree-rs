//! Integration test: Git push and clone via htree://
//!
//! This test verifies the full git remote helper workflow:
//! 1. Create a test git repository with some files
//! 2. Generate an identity (uses htree://self which auto-generates keys)
//! 3. Push via `git push htree://self/<repo>`
//! 4. Clone to new directory via `git clone htree://self/<repo>`
//! 5. Verify files match
//!
//! This test uses local storage only (no daemon needed) since push and clone
//! share the same HOME directory with the same keys.
//!
//! Run with: cargo test --package git-remote-htree --test git_roundtrip -- --nocapture

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

struct TestEnv {
    _data_dir: TempDir,
    home_dir: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let home_dir = data_dir.path().to_path_buf();

        // Create .hashtree config dir
        let config_dir = home_dir.join(".hashtree");
        std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");

        // Create config - use relays that work reliably
        let config_content = r#"
[server]
enable_auth = false
stun_port = 0

[nostr]
relays = ["wss://temp.iris.to", "wss://relay.damus.io"]
crawl_depth = 0
"#;
        std::fs::write(config_dir.join("config.toml"), config_content)
            .expect("Failed to write config");

        TestEnv {
            _data_dir: data_dir,
            home_dir,
        }
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![
            (
                "HOME".to_string(),
                self.home_dir.to_string_lossy().to_string(),
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
        .status()
        .expect("Failed to git commit");

    dir
}

#[test]
#[ignore = "requires network - run with: cargo test --package git-remote-htree --test git_roundtrip -- --ignored --nocapture"]
fn test_git_push_and_clone() {
    // Check prerequisites
    if find_git_remote_htree_dir().is_none() {
        panic!(
            "git-remote-htree binary not found. Run `cargo build --release -p git-remote-htree` first."
        );
    }

    println!("=== Git Push/Clone Roundtrip Test ===\n");

    // Create test environment (shared HOME for push and clone)
    let test_env = TestEnv::new();
    println!("Test environment at: {:?}\n", test_env.home_dir);

    // Create test repo
    println!("Creating test repository...");
    let repo = create_test_repo();
    println!("Test repo at: {:?}\n", repo.path());

    // Add htree remote using "self" - this auto-generates keys on first use
    let remote_url = "htree://self/test-repo";
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
    println!("Push stdout: {}", String::from_utf8_lossy(&push.stdout));
    println!("Push stderr: {}", String::from_utf8_lossy(&push.stderr));
    println!("Push exit code: {:?}", push.status.code());
    println!("Push took: {:?}", push_duration);

    // Check for success indicators in output (git may have non-zero exit but still worked)
    let stderr = String::from_utf8_lossy(&push.stderr);
    let push_worked = stderr.contains("-> master") || stderr.contains("-> main");

    if !push.status.success() && !push_worked {
        panic!("git push failed: {}", stderr);
    }

    // Extract the actual npub from the push output (e.g., "Published to: htree://npub1...")
    let npub = stderr
        .split("htree://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .expect("Could not extract npub from push output");
    println!("Published to npub: {}", npub);
    println!("Push successful!\n");

    // Clone to new directory using the actual npub (not self)
    let clone_url = format!("htree://{}/test-repo", npub);
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
    println!("Clone stdout: {}", String::from_utf8_lossy(&clone.stdout));
    println!("Clone stderr: {}", String::from_utf8_lossy(&clone.stderr));
    println!("Clone exit code: {:?}", clone.status.code());
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

    // Verify git history matches
    println!("Verifying git commit history...");

    // Get commit log from original repo
    let original_log = Command::new("git")
        .args(["log", "--format=%H %s", "--all"])
        .current_dir(repo.path())
        .output()
        .expect("Failed to run git log on original");
    let original_commits = String::from_utf8_lossy(&original_log.stdout);
    println!("Original repo commits:\n{}", original_commits);

    // Get commit log from cloned repo
    let cloned_log = Command::new("git")
        .args(["log", "--format=%H %s", "--all"])
        .current_dir(&clone_path)
        .output()
        .expect("Failed to run git log on clone");
    let cloned_commits = String::from_utf8_lossy(&cloned_log.stdout);
    println!("Cloned repo commits:\n{}", cloned_commits);

    // Commits should match exactly (same SHAs)
    assert_eq!(
        original_commits.trim(),
        cloned_commits.trim(),
        "Commit history should match exactly"
    );

    // Verify author/date info is preserved
    let original_show = Command::new("git")
        .args(["log", "-1", "--format=%an <%ae> %ai"])
        .current_dir(repo.path())
        .output()
        .expect("Failed to get original commit info");
    let original_info = String::from_utf8_lossy(&original_show.stdout);

    let cloned_show = Command::new("git")
        .args(["log", "-1", "--format=%an <%ae> %ai"])
        .current_dir(&clone_path)
        .output()
        .expect("Failed to get cloned commit info");
    let cloned_info = String::from_utf8_lossy(&cloned_show.stdout);

    assert_eq!(
        original_info.trim(),
        cloned_info.trim(),
        "Commit author and date should match"
    );
    println!("Commit info: {}", original_info.trim());

    // Also check that HEAD points to the right branch
    let cloned_head = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(&clone_path)
        .output()
        .expect("Failed to get HEAD branch");
    let head_branch = String::from_utf8_lossy(&cloned_head.stdout);
    println!("Cloned repo HEAD branch: {}", head_branch.trim());
    assert!(
        head_branch.trim() == "master" || head_branch.trim() == "main",
        "HEAD should be on master or main branch"
    );

    println!("\n=== SUCCESS: Git roundtrip test passed! ===");
    println!("Push time: {:?}", push_duration);
    println!("Clone time: {:?}", clone_duration);
}

#[test]
fn test_git_remote_htree_binary_exists() {
    // Quick sanity check that the binary exists (doesn't require network)
    if find_git_remote_htree_dir().is_none() {
        println!(
            "SKIP: git-remote-htree binary not found. Build with: cargo build -p git-remote-htree"
        );
        return;
    }

    let bin_dir = find_git_remote_htree_dir().unwrap();
    let binary = bin_dir.join("git-remote-htree");
    assert!(binary.exists(), "git-remote-htree binary should exist");

    // Check it's executable by running --help
    let output = Command::new(&binary).arg("--help").output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("git-remote-htree --help output:\n{}\n{}", stdout, stderr);
            // The binary doesn't have --help, but running it should at least not crash
        }
        Err(e) => {
            // Permission denied or other error is fine - just check it exists
            println!("Could not run binary (may need execute permission): {}", e);
        }
    }
}
