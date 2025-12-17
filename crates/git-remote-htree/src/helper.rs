//! Git remote helper protocol implementation
//!
//! Implements the stateless git remote helper protocol.
//! See: https://git-scm.com/docs/gitremote-helpers

use anyhow::{bail, Context, Result};
use crate::git::object::ObjectType;
use crate::git::refs::Ref;
use crate::git::storage::GitStorage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::nostr_client::NostrClient;

/// Get the shared hashtree data directory
/// Can be overridden with HTREE_DATA_DIR environment variable
fn get_hashtree_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HTREE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".hashtree")
        .join("data")
}

/// Git remote helper state machine
pub struct RemoteHelper {
    #[allow(dead_code)]
    pubkey: String,
    repo_name: String,
    storage: GitStorage,
    nostr: NostrClient,
    #[allow(dead_code)]
    config: Config,
    should_exit: bool,
    /// Refs advertised by remote
    remote_refs: HashMap<String, String>,
    /// Objects to push
    push_specs: Vec<PushSpec>,
    /// Objects to fetch
    fetch_specs: Vec<FetchSpec>,
}

#[derive(Debug)]
struct PushSpec {
    src: String, // local ref or sha
    dst: String, // remote ref
    force: bool,
}

#[derive(Debug)]
struct FetchSpec {
    sha: String,
    name: String,
}

impl RemoteHelper {
    pub fn new(pubkey: &str, repo_name: &str, secret_key: Option<String>, config: Config) -> Result<Self> {
        // Use shared hashtree storage at ~/.hashtree/data
        let storage = GitStorage::open(get_hashtree_data_dir())?;
        let nostr = NostrClient::new(pubkey, secret_key, &config)?;

        Ok(Self {
            pubkey: pubkey.to_string(),
            repo_name: repo_name.to_string(),
            storage,
            nostr,
            config,
            should_exit: false,
            remote_refs: HashMap::new(),
            push_specs: Vec::new(),
            fetch_specs: Vec::new(),
        })
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    /// Handle a single command from git
    pub fn handle_command(&mut self, line: &str) -> Result<Option<Vec<String>>> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).copied();

        match cmd {
            "capabilities" => Ok(Some(self.capabilities())),
            "list" => {
                let for_push = arg == Some("for-push");
                self.list_refs(for_push)
            }
            "fetch" => {
                if let Some(arg) = arg {
                    self.queue_fetch(arg)?;
                }
                Ok(None)
            }
            "push" => {
                if let Some(arg) = arg {
                    self.queue_push(arg)?;
                }
                Ok(None)
            }
            "" => {
                // Empty line - execute queued operations
                if !self.fetch_specs.is_empty() {
                    self.execute_fetch()?;
                }
                if !self.push_specs.is_empty() {
                    return self.execute_push();
                }
                // Final empty line means exit
                self.should_exit = true;
                Ok(Some(vec![String::new()]))
            }
            "option" => {
                // Options like "option verbosity 1"
                debug!("Ignoring option: {:?}", arg);
                Ok(Some(vec!["unsupported".to_string()]))
            }
            _ => {
                warn!("Unknown command: {}", cmd);
                Ok(None)
            }
        }
    }

    /// Return supported capabilities
    fn capabilities(&self) -> Vec<String> {
        vec![
            "fetch".to_string(),
            "push".to_string(),
            "option".to_string(),
            String::new(), // Empty line terminates
        ]
    }

    /// List refs available on remote
    fn list_refs(&mut self, _for_push: bool) -> Result<Option<Vec<String>>> {
        // Fetch refs from nostr
        let refs = self.nostr.fetch_refs(&self.repo_name)?;

        let mut lines = Vec::new();
        self.remote_refs.clear();

        for (name, sha) in &refs {
            self.remote_refs.insert(name.clone(), sha.clone());
            if name == "HEAD" {
                // HEAD is a symref
                if let Some(target) = refs
                    .get("refs/heads/main")
                    .or_else(|| refs.get("refs/heads/master"))
                {
                    lines.push("@refs/heads/main HEAD".to_string());
                    // Also list the actual sha
                    lines.push(format!("{} HEAD", target));
                }
            } else {
                lines.push(format!("{} {}", sha, name));
            }
        }

        // Empty repo
        if lines.is_empty() {
            debug!("Remote has no refs");
        }

        lines.push(String::new()); // Empty line terminates
        Ok(Some(lines))
    }

    /// Queue a fetch operation
    fn queue_fetch(&mut self, arg: &str) -> Result<()> {
        // Format: <sha> <name>
        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
        if parts.len() != 2 {
            bail!("Invalid fetch spec: {}", arg);
        }

        self.fetch_specs.push(FetchSpec {
            sha: parts[0].to_string(),
            name: parts[1].to_string(),
        });
        Ok(())
    }

    /// Execute queued fetch operations
    fn execute_fetch(&mut self) -> Result<()> {
        info!("Fetching {} refs", self.fetch_specs.len());

        // Get the cached root hash from nostr (set during list command)
        let root_hash = self.nostr.get_cached_root_hash(&self.repo_name).cloned();

        if let Some(ref root) = root_hash {
            // Fetch all git objects from the hashtree structure
            let objects = self.fetch_all_git_objects(root)?;
            info!("Downloaded {} git objects from hashtree", objects.len());

            // Store in local git
            for (oid, data) in objects {
                self.write_git_object(&oid, &data)?;
            }
        } else {
            // Fallback to original per-ref fetch (will likely fail)
            for spec in &self.fetch_specs {
                debug!("Fetching {} ({})", spec.name, spec.sha);
                let objects = self.fetch_objects_via_htree(&spec.sha)?;
                for (oid, data) in objects {
                    self.write_git_object(&oid, &data)?;
                }
            }
        }

        self.fetch_specs.clear();
        Ok(())
    }

    /// Fetch all git objects from hashtree's .git/objects/ directory
    fn fetch_all_git_objects(&self, root_hash: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let encryption_key = self.nostr.get_cached_encryption_key(&self.repo_name).cloned();

        // Create tokio runtime for async blossom downloads
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        rt.block_on(self.fetch_git_objects_async(root_hash, encryption_key.as_ref()))
    }

    /// Async implementation of git object fetching
    async fn fetch_git_objects_async(
        &self,
        root_hash: &str,
        encryption_key: Option<&[u8; 32]>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        use hashtree_core::{decode_tree_node, decrypt_chk};

        let blossom = self.nostr.blossom();
        let mut objects = Vec::new();

        // Helper to decrypt and decode a tree node
        let decrypt_and_decode = |data: &[u8], key: Option<&[u8; 32]>| -> Option<hashtree_core::TreeNode> {
            let decrypted = if let Some(k) = key {
                match decrypt_chk(data, k) {
                    Ok(d) => d,
                    Err(_) => return None,
                }
            } else {
                data.to_vec()
            };
            decode_tree_node(&decrypted).ok()
        };

        // Download root
        let root_data = match blossom.try_download(root_hash).await {
            Some(data) => data,
            None => {
                warn!("Could not download root hash {}", root_hash);
                return Ok(objects);
            }
        };

        let root_node = match decrypt_and_decode(&root_data, encryption_key) {
            Some(node) => node,
            None => return Ok(objects),
        };

        // Find .git directory
        let git_link = root_node.links.iter().find(|l| l.name.as_deref() == Some(".git"));
        let (git_hash, git_key) = match git_link {
            Some(link) => (hex::encode(link.hash), link.key),
            None => return Ok(objects),
        };

        let git_data = match blossom.try_download(&git_hash).await {
            Some(data) => data,
            None => return Ok(objects),
        };

        let git_node = match decrypt_and_decode(&git_data, git_key.as_ref()) {
            Some(node) => node,
            None => return Ok(objects),
        };

        // Find objects directory
        let objects_link = git_node.links.iter().find(|l| l.name.as_deref() == Some("objects"));
        let (objects_hash, objects_key) = match objects_link {
            Some(link) => (hex::encode(link.hash), link.key),
            None => return Ok(objects),
        };

        let objects_data = match blossom.try_download(&objects_hash).await {
            Some(data) => data,
            None => return Ok(objects),
        };

        let objects_node = match decrypt_and_decode(&objects_data, objects_key.as_ref()) {
            Some(node) => node,
            None => return Ok(objects),
        };

        // Git loose objects are stored as objects/XX/YYYYYYYY...
        // where XX is first 2 hex chars (directory) and rest is the filename
        for prefix_link in &objects_node.links {
            let prefix = match &prefix_link.name {
                Some(n) => n.clone(),
                None => continue,
            };

            // Skip pack files and info for now (we only support loose objects)
            if prefix == "pack" || prefix == "info" {
                continue;
            }

            // Skip non-hex directory names (must be 2 hex chars)
            if prefix.len() != 2 || hex::decode(&prefix).is_err() {
                continue;
            }

            // Download the prefix subdirectory
            let prefix_hash = hex::encode(prefix_link.hash);
            let prefix_data = match blossom.try_download(&prefix_hash).await {
                Some(data) => data,
                None => continue,
            };

            let prefix_node = match decrypt_and_decode(&prefix_data, prefix_link.key.as_ref()) {
                Some(node) => node,
                None => continue,
            };

            // Iterate over objects in this subdirectory
            for obj_link in &prefix_node.links {
                let suffix = match &obj_link.name {
                    Some(n) => n.clone(),
                    None => continue,
                };

                // Full git object id is prefix + suffix
                let oid = format!("{}{}", prefix, suffix);

                // Download the object data
                let obj_hash = hex::encode(obj_link.hash);
                let obj_data = match blossom.try_download(&obj_hash).await {
                    Some(data) => data,
                    None => continue,
                };

                // Decrypt if needed
                let obj_content = if let Some(k) = obj_link.key.as_ref() {
                    match decrypt_chk(&obj_data, k) {
                        Ok(d) => d,
                        Err(_) => continue,
                    }
                } else {
                    obj_data
                };

                // This is the zlib-compressed loose object
                objects.push((oid, obj_content));
            }
        }

        debug!("Fetched {} git objects from hashtree", objects.len());
        Ok(objects)
    }

    /// Fetch objects using htree CLI (which has file server fallback)
    fn fetch_objects_via_htree(&self, root_hash: &str) -> Result<Vec<(String, Vec<u8>)>> {
        // First, try to get the root hash content via htree get
        let output = Command::new("htree")
            .args(["get", root_hash])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match output {
            Ok(out) if out.status.success() => {
                // htree get outputs raw content - for git repos this is the tree structure
                // Parse and recursively fetch git objects
                let content = out.stdout;
                debug!("Fetched {} bytes for {}", content.len(), root_hash);

                // The hashtree stores git objects - return them for unpacking
                // TODO: Parse the hashtree structure to get individual git objects
                // For now, return empty - needs full implementation
                Ok(vec![])
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                debug!("htree get failed for {}: {}", root_hash, stderr);
                // Not found locally or on file servers
                Ok(vec![])
            }
            Err(e) => {
                warn!("Failed to run htree get: {}", e);
                Ok(vec![])
            }
        }
    }

    /// Write loose object to local git object store
    /// The data is zlib-compressed loose object format - decompress and use git hash-object
    fn write_git_object(&self, oid: &str, data: &[u8]) -> Result<()> {
        use flate2::read::ZlibDecoder;
        use std::io::Read;

        // Git objects are stored as .git/objects/xx/yy... where xx is first 2 chars
        if oid.len() < 3 {
            bail!("Invalid object id: {}", oid);
        }

        // Decompress the zlib data to get the raw git object (header + content)
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .context("Failed to decompress git object")?;

        // Parse git object format: "<type> <size>\0<content>"
        let null_pos = decompressed.iter().position(|&b| b == 0)
            .context("Invalid git object: no null byte")?;

        let header = std::str::from_utf8(&decompressed[..null_pos])
            .context("Invalid git object header")?;

        let content = &decompressed[null_pos + 1..];

        // Parse header to get type
        let parts: Vec<&str> = header.split(' ').collect();
        if parts.len() != 2 {
            bail!("Invalid git object header: {}", header);
        }
        let obj_type = parts[0];

        // Use git hash-object to write the object - this works during clone
        // because git sets GIT_DIR for the remote helper
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "-t", obj_type, "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn git hash-object")?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(content)?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git hash-object failed: {}", stderr);
        }

        let written_oid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if written_oid != oid {
            warn!("Object hash mismatch: expected {}, got {}", oid, written_oid);
        }

        debug!("Wrote git object {} via hash-object", oid);
        Ok(())
    }

    /// Queue a push operation
    fn queue_push(&mut self, arg: &str) -> Result<()> {
        // Format: [+]<src>:<dst>
        let force = arg.starts_with('+');
        let arg = if force { &arg[1..] } else { arg };

        let parts: Vec<&str> = arg.splitn(2, ':').collect();
        if parts.len() != 2 {
            bail!("Invalid push spec: {}", arg);
        }

        self.push_specs.push(PushSpec {
            src: parts[0].to_string(),
            dst: parts[1].to_string(),
            force,
        });
        Ok(())
    }

    /// Execute queued push operations
    fn execute_push(&mut self) -> Result<Option<Vec<String>>> {
        info!("Pushing {} refs", self.push_specs.len());

        let mut results = Vec::new();

        // Clone specs to avoid borrow issues
        let specs: Vec<_> = std::mem::take(&mut self.push_specs);

        for spec in specs {
            debug!(
                "Pushing {} -> {} (force={})",
                spec.src, spec.dst, spec.force
            );

            // Resolve src to sha
            let sha = if spec.src.is_empty() {
                // Delete ref
                String::new()
            } else {
                self.resolve_ref(&spec.src)?
            };

            if sha.is_empty() {
                // Delete
                match self.storage.delete_ref(&spec.dst) {
                    Ok(_) => {
                        self.nostr.delete_ref(&self.repo_name, &spec.dst)?;
                        results.push(format!("ok {}", spec.dst));
                    }
                    Err(e) => results.push(format!("error {} {}", spec.dst, e)),
                }
            } else {
                // Push objects
                match self.push_objects(&sha, &spec.dst) {
                    Ok(()) => results.push(format!("ok {}", spec.dst)),
                    Err(e) => results.push(format!("error {} {}", spec.dst, e)),
                }
            }
        }

        results.push(String::new()); // Empty line terminates
        Ok(Some(results))
    }

    /// Resolve a ref to its sha
    fn resolve_ref(&self, refspec: &str) -> Result<String> {
        let output = Command::new("git").args(["rev-parse", refspec]).output()?;

        if !output.status.success() {
            bail!("Failed to resolve ref: {}", refspec);
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Push all objects reachable from sha
    fn push_objects(&mut self, sha: &str, dst_ref: &str) -> Result<()> {
        // Get list of objects to push
        let objects = self.list_objects_to_push(sha)?;

        info!("Pushing {} objects for {}", objects.len(), sha);

        // Read and store each object using hashtree-git's storage
        for oid in &objects {
            let (obj_type, content) = self.read_git_object_with_type(oid)?;
            self.storage.write_raw_object(obj_type, &content)?;
        }

        // Update ref in storage
        let oid = crate::git::object::ObjectId::from_hex(sha)
            .ok_or_else(|| anyhow::anyhow!("Invalid object id: {}", sha))?;
        self.storage.write_ref(dst_ref, &Ref::Direct(oid))?;

        // Build the merkle tree
        let root_hash = self.storage.get_root_hash()?;

        // Publish to nostr (kind 30078 with hashtree label)
        self.nostr.publish_repo(&self.repo_name, &root_hash)?;

        // Push to file servers (blossom) in background
        // This makes content available even without P2P connection
        self.push_to_file_servers(&root_hash);

        Ok(())
    }

    /// Push content to file servers (blossom)
    /// Uploads all blobs from local LMDB store to Blossom servers
    fn push_to_file_servers(&self, _root_hash: &str) {
        let store = self.storage.store();
        let blossom = self.nostr.blossom();

        // Get all hashes from LMDB
        let hashes = match store.list() {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to list blobs for upload: {}", e);
                return;
            }
        };

        info!("Uploading {} blobs to file servers", hashes.len());

        // Create runtime for async uploads
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                warn!("Failed to create runtime for blossom upload: {}", e);
                return;
            }
        };

        rt.block_on(async {
            let mut uploaded = 0;
            let mut skipped = 0;
            let mut failed = 0;

            for hash in hashes {
                // Get blob data from LMDB
                let data = match store.get_sync(&hash) {
                    Ok(Some(d)) => d,
                    Ok(None) => continue,
                    Err(e) => {
                        debug!("Failed to read blob {}: {}", hex::encode(hash), e);
                        failed += 1;
                        continue;
                    }
                };

                // Upload to Blossom (skip if already exists)
                match blossom.upload_if_missing(&data).await {
                    Ok((_, true)) => uploaded += 1,
                    Ok((_, false)) => skipped += 1,
                    Err(e) => {
                        debug!("Failed to upload blob {}: {}", hex::encode(hash), e);
                        failed += 1;
                    }
                }
            }

            info!(
                "Blossom upload complete: {} uploaded, {} already existed, {} failed",
                uploaded, skipped, failed
            );
        });
    }

    /// List objects that need to be pushed (not on remote)
    fn list_objects_to_push(&self, sha: &str) -> Result<Vec<String>> {
        // Get all objects reachable from sha
        let output = Command::new("git")
            .args(["rev-list", "--objects", sha])
            .output()?;

        if !output.status.success() {
            bail!("Failed to list objects");
        }

        let mut objects = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            // Format: <sha> [path]
            if let Some(oid) = line.split_whitespace().next() {
                objects.push(oid.to_string());
            }
        }

        Ok(objects)
    }

    /// Read object from local git with its type
    fn read_git_object_with_type(&self, oid: &str) -> Result<(ObjectType, Vec<u8>)> {
        // Get object type
        let type_output = Command::new("git").args(["cat-file", "-t", oid]).output()?;
        if !type_output.status.success() {
            bail!("Failed to get object type: {}", oid);
        }
        let type_str = String::from_utf8_lossy(&type_output.stdout).trim().to_string();

        let obj_type = match type_str.as_str() {
            "blob" => ObjectType::Blob,
            "tree" => ObjectType::Tree,
            "commit" => ObjectType::Commit,
            "tag" => ObjectType::Tag,
            _ => bail!("Unknown object type: {}", type_str),
        };

        // Get object content
        let content_output = Command::new("git").args(["cat-file", "-p", oid]).output()?;
        if !content_output.status.success() {
            bail!("Failed to read object: {}", oid);
        }

        Ok((obj_type, content_output.stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBKEY: &str = "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";

    fn create_test_helper() -> Option<RemoteHelper> {
        let config = Config::default();
        RemoteHelper::new(TEST_PUBKEY, "test-repo", None, config).ok()
    }

    #[test]
    fn test_capabilities() {
        let Some(helper) = create_test_helper() else {
            return; // Skip if storage can't be created
        };

        let caps = helper.capabilities();
        assert!(caps.contains(&"fetch".to_string()));
        assert!(caps.contains(&"push".to_string()));
        assert!(caps.contains(&"option".to_string()));
        // Should end with empty line
        assert_eq!(caps.last(), Some(&String::new()));
    }

    #[test]
    fn test_handle_capabilities_command() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        let result = helper.handle_command("capabilities").unwrap();
        assert!(result.is_some());
        let caps = result.unwrap();
        assert!(caps.contains(&"fetch".to_string()));
        assert!(caps.contains(&"push".to_string()));
    }

    #[test]
    fn test_handle_list_command() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // list should return refs (empty for new repo)
        let result = helper.handle_command("list").unwrap();
        assert!(result.is_some());
        let lines = result.unwrap();
        // Should end with empty line
        assert_eq!(lines.last(), Some(&String::new()));
    }

    #[test]
    fn test_handle_list_for_push_command() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        let result = helper.handle_command("list for-push").unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_handle_option_command() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        let result = helper.handle_command("option verbosity 1").unwrap();
        assert!(result.is_some());
        let lines = result.unwrap();
        assert!(lines.contains(&"unsupported".to_string()));
    }

    #[test]
    fn test_handle_unknown_command() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        let result = helper.handle_command("unknown-command").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_empty_line_exits() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        assert!(!helper.should_exit());
        let _ = helper.handle_command("").unwrap();
        assert!(helper.should_exit());
    }

    #[test]
    fn test_queue_fetch() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Queue a fetch
        let result = helper.handle_command("fetch abc123def456 refs/heads/main").unwrap();
        assert!(result.is_none()); // fetch queues, doesn't respond immediately

        assert_eq!(helper.fetch_specs.len(), 1);
        assert_eq!(helper.fetch_specs[0].sha, "abc123def456");
        assert_eq!(helper.fetch_specs[0].name, "refs/heads/main");
    }

    #[test]
    fn test_queue_multiple_fetches() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        helper.handle_command("fetch abc123 refs/heads/main").unwrap();
        helper.handle_command("fetch def456 refs/heads/feature").unwrap();

        assert_eq!(helper.fetch_specs.len(), 2);
    }

    #[test]
    fn test_queue_fetch_invalid() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Missing name
        let result = helper.handle_command("fetch abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_queue_push() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        let result = helper.handle_command("push refs/heads/main:refs/heads/main").unwrap();
        assert!(result.is_none()); // push queues, doesn't respond immediately

        assert_eq!(helper.push_specs.len(), 1);
        assert_eq!(helper.push_specs[0].src, "refs/heads/main");
        assert_eq!(helper.push_specs[0].dst, "refs/heads/main");
        assert!(!helper.push_specs[0].force);
    }

    #[test]
    fn test_queue_force_push() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        helper.handle_command("push +refs/heads/main:refs/heads/main").unwrap();

        assert_eq!(helper.push_specs.len(), 1);
        assert!(helper.push_specs[0].force);
    }

    #[test]
    fn test_queue_delete_push() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Empty src means delete
        helper.handle_command("push :refs/heads/old-branch").unwrap();

        assert_eq!(helper.push_specs.len(), 1);
        assert_eq!(helper.push_specs[0].src, "");
        assert_eq!(helper.push_specs[0].dst, "refs/heads/old-branch");
    }

    #[test]
    fn test_queue_push_invalid() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Missing colon separator
        let result = helper.handle_command("push refs/heads/main");
        assert!(result.is_err());
    }

    #[test]
    fn test_push_spec_parsing() {
        // Test internal PushSpec parsing via queue_push
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Normal push
        helper.queue_push("src:dst").unwrap();
        assert_eq!(helper.push_specs[0].src, "src");
        assert_eq!(helper.push_specs[0].dst, "dst");
        assert!(!helper.push_specs[0].force);

        helper.push_specs.clear();

        // Force push
        helper.queue_push("+src:dst").unwrap();
        assert!(helper.push_specs[0].force);
        assert_eq!(helper.push_specs[0].src, "src");

        helper.push_specs.clear();

        // Delete (empty src)
        helper.queue_push(":dst").unwrap();
        assert_eq!(helper.push_specs[0].src, "");
        assert_eq!(helper.push_specs[0].dst, "dst");
    }

    #[test]
    fn test_fetch_spec_parsing() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        helper.queue_fetch("abc123def456789 refs/heads/main").unwrap();

        assert_eq!(helper.fetch_specs[0].sha, "abc123def456789");
        assert_eq!(helper.fetch_specs[0].name, "refs/heads/main");
    }

    #[test]
    fn test_fetch_spec_with_tag() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        helper.queue_fetch("abc123 refs/tags/v1.0.0").unwrap();
        assert_eq!(helper.fetch_specs[0].name, "refs/tags/v1.0.0");
    }

    #[test]
    fn test_should_exit_initially_false() {
        let Some(helper) = create_test_helper() else {
            return;
        };

        assert!(!helper.should_exit());
    }

    #[test]
    fn test_get_hashtree_data_dir() {
        let dir = get_hashtree_data_dir();
        assert!(dir.ends_with("data"));
        assert!(dir.to_string_lossy().contains(".hashtree"));
    }

    #[test]
    fn test_command_parsing_with_spaces() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Commands are split by first space only
        let result = helper.handle_command("option verbosity 1").unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_list_clears_remote_refs() {
        let Some(mut helper) = create_test_helper() else {
            return;
        };

        // Add some dummy refs
        helper.remote_refs.insert("refs/heads/old".to_string(), "abc".to_string());

        // list should clear and repopulate
        helper.handle_command("list").unwrap();

        // For empty repo, refs should be empty
        assert!(helper.remote_refs.is_empty());
    }
}
