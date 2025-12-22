//! Git remote helper protocol implementation
//!
//! Implements the stateless git remote helper protocol.
//! See: https://git-scm.com/docs/gitremote-helpers

use anyhow::{bail, Context, Result};
use crate::git::object::ObjectType;
use crate::git::refs::Ref;
use crate::git::storage::GitStorage;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use hashtree_config::Config;
use crate::nostr_client::NostrClient;

/// Get the shared hashtree data directory
fn get_hashtree_data_dir() -> PathBuf {
    hashtree_config::get_data_dir()
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
    fn list_refs(&mut self, for_push: bool) -> Result<Option<Vec<String>>> {
        // For push, always return empty refs to force re-push
        // This ensures content is always re-uploaded to blossom servers
        // and we regenerate the index file each time
        if for_push {
            debug!("Returning empty refs for push to force re-upload");
            self.remote_refs.clear();
            return Ok(Some(vec![String::new()]));
        }

        // For clone/pull, fetch actual refs from nostr
        let refs = self.nostr.fetch_refs(&self.repo_name)?;

        let mut lines = Vec::new();
        self.remote_refs.clear();

        for (name, sha) in &refs {
            self.remote_refs.insert(name.clone(), sha.clone());
            if name == "HEAD" {
                // HEAD is a symref - check for actual target branch
                if let Some(target_branch) = sha.strip_prefix("ref: ") {
                    // Symbolic ref (e.g., "ref: refs/heads/main")
                    if let Some(target_sha) = refs.get(target_branch) {
                        lines.push(format!("@{} HEAD", target_branch));
                        lines.push(format!("{} HEAD", target_sha));
                    }
                } else if let Some((branch, target)) = refs
                    .get("refs/heads/main")
                    .map(|t| ("refs/heads/main", t))
                    .or_else(|| refs.get("refs/heads/master").map(|t| ("refs/heads/master", t)))
                {
                    // Direct SHA in HEAD, find the matching branch
                    lines.push(format!("@{} HEAD", branch));
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

        // Update local refs to point to the fetched commits
        // Use git update-ref since git sets GIT_DIR for the remote helper
        for spec in &self.fetch_specs {
            let output = Command::new("git")
                .args(["update-ref", &spec.name, &spec.sha])
                .output()
                .context("Failed to run git update-ref")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to update ref {}: {}", spec.name, stderr);
            } else {
                debug!("Updated {} -> {}", spec.name, &spec.sha[..12]);
            }
        }

        self.fetch_specs.clear();
        Ok(())
    }

    /// Fetch all git objects from hashtree's .git/objects/ directory
    fn fetch_all_git_objects(&self, root_hash: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let encryption_key = self.nostr.get_cached_encryption_key(&self.repo_name).cloned();
        info!("fetch_all_git_objects: root={}, has encryption_key: {}", &root_hash[..12], encryption_key.is_some());

        // Create tokio runtime for async blossom downloads
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        rt.block_on(self.fetch_git_objects_async(root_hash, encryption_key.as_ref()))
    }

    /// Async implementation of git object fetching using HashTree helpers
    async fn fetch_git_objects_async(
        &self,
        root_hash: &str,
        encryption_key: Option<&[u8; 32]>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        use hashtree_blossom::BlossomStore;
        use hashtree_core::{Cid, HashTree, HashTreeConfig};

        let blossom = self.nostr.blossom();
        let mut objects = Vec::new();

        // Log the servers being used
        let servers = blossom.read_servers().to_vec();
        info!("Creating BlossomStore with servers: {:?}", servers);

        // Create a BlossomStore-backed HashTree for reading
        // Use the same read servers from the existing blossom client
        let store = BlossomStore::with_servers(
            nostr::Keys::generate(), // Temporary keys for read-only ops
            servers,
        );
        let tree = HashTree::new(HashTreeConfig::new(std::sync::Arc::new(store)));

        // Parse root hash and create Cid with encryption key
        let root_bytes = hex::decode(root_hash)
            .context("Invalid root hash hex")?;
        let root_arr: [u8; 32] = root_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Root hash must be 32 bytes"))?;

        let root_cid = Cid {
            hash: root_arr,
            key: encryption_key.copied(),
            size: 0,
        };

        // Resolve .git/objects path
        let objects_cid = match tree.resolve_path(&root_cid, ".git/objects").await {
            Ok(Some(cid)) => cid,
            Ok(None) => {
                warn!("No .git/objects directory found");
                return Ok(objects);
            }
            Err(e) => {
                warn!("Failed to resolve .git/objects: {}", e);
                return Ok(objects);
            }
        };

        info!("Resolved .git/objects: {}", hex::encode(objects_cid.hash));

        // List objects directory
        let entries = match tree.list_directory(&objects_cid).await {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to list objects directory: {}", e);
                return Ok(objects);
            }
        };

        use futures::stream::{self, StreamExt};
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        // Collect all objects to fetch (oid, cid) pairs
        let is_prefix_layout = entries.iter().any(|e| e.name.len() == 2);
        let mut fetch_tasks: Vec<(String, Cid)> = Vec::new();

        if is_prefix_layout {
            for entry in &entries {
                if entry.name.len() != 2 || hex::decode(&entry.name).is_err() {
                    continue;
                }
                let prefix = entry.name.clone();
                let prefix_cid = Cid {
                    hash: entry.hash,
                    key: entry.key,
                    size: entry.size,
                };
                if let Ok(sub_entries) = tree.list_directory(&prefix_cid).await {
                    for obj_entry in sub_entries {
                        if obj_entry.name.len() != 38 || hex::decode(&obj_entry.name).is_err() {
                            continue;
                        }
                        let oid = format!("{}{}", prefix, obj_entry.name);
                        let obj_cid = Cid {
                            hash: obj_entry.hash,
                            key: obj_entry.key,
                            size: obj_entry.size,
                        };
                        fetch_tasks.push((oid, obj_cid));
                    }
                }
            }
        } else {
            for entry in &entries {
                if entry.name.len() != 40 || hex::decode(&entry.name).is_err() {
                    continue;
                }
                let oid = entry.name.clone();
                let obj_cid = Cid {
                    hash: entry.hash,
                    key: entry.key,
                    size: entry.size,
                };
                fetch_tasks.push((oid, obj_cid));
            }
        }

        let total_objects = fetch_tasks.len();
        eprintln!("  Downloading {} git objects...", total_objects);
        let downloaded = StdArc::new(AtomicUsize::new(0));

        // Parallel fetch with concurrency limit
        const CONCURRENCY: usize = 20;
        let results: Vec<Option<(String, Vec<u8>)>> = stream::iter(fetch_tasks)
            .map(|(oid, obj_cid)| {
                let tree = &tree;
                let downloaded = StdArc::clone(&downloaded);
                async move {
                    let result = tree.get(&obj_cid).await.ok().flatten().map(|content| (oid, content));
                    let count = downloaded.fetch_add(1, Ordering::Relaxed) + 1;
                    if count % 20 == 0 || count == total_objects {
                        eprint!("\r  Downloading: {}/{}", count, total_objects);
                        let _ = std::io::stderr().flush();
                    }
                    result
                }
            })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;

        eprintln!(); // Newline after progress

        for result in results {
            if let Some((oid, content)) = result {
                objects.push((oid, content));
            }
        }

        info!("Fetched {} git objects from hashtree", objects.len());
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
        eprint!("  Listing objects...");
        let _ = std::io::stderr().flush();
        let objects = self.list_objects_to_push(sha)?;
        eprintln!(" {} objects", objects.len());

        info!("Pushing {} objects for {}", objects.len(), sha);

        // Read all objects in batch using git cat-file --batch
        let objects_with_content = self.read_git_objects_batch(&objects)?;
        eprintln!(); // Newline after reading progress

        eprint!("  Writing to store...");
        let _ = std::io::stderr().flush();
        let total = objects_with_content.len();
        for (i, (obj_type, content)) in objects_with_content.into_iter().enumerate() {
            self.storage.write_raw_object(obj_type, &content)?;
            if (i + 1) % 1000 == 0 || i + 1 == total {
                eprint!("\r  Writing to store: {}/{}", i + 1, total);
                let _ = std::io::stderr().flush();
            }
        }
        eprintln!();

        // Update ref in storage
        let oid = crate::git::object::ObjectId::from_hex(sha)
            .ok_or_else(|| anyhow::anyhow!("Invalid object id: {}", sha))?;
        self.storage.write_ref(dst_ref, &Ref::Direct(oid))?;

        // Set HEAD to point to this branch if it's a branch ref
        // This is needed for wasm-git to detect the current branch
        if dst_ref.starts_with("refs/heads/") {
            self.storage.write_ref("HEAD", &Ref::Symbolic(dst_ref.to_string()))?;
            debug!("Set HEAD -> {}", dst_ref);
        }

        // Build the merkle tree
        eprint!("  Building merkle tree...");
        let _ = std::io::stderr().flush();
        let root_hash = self.storage.build_tree()?;
        let root_hash_hex = hex::encode(root_hash);
        eprintln!(" done");

        // Push to file servers (blossom) first
        // This makes content available before we advertise the hash
        let blossom_count = self.push_to_file_servers(&root_hash_hex);

        // Then publish to nostr (kind 30078 with hashtree label)
        // Don't fail push if relay publish fails - it's just distribution
        let (npub_url, relay_count) = match self.nostr.publish_repo(&self.repo_name, &root_hash_hex) {
            Ok((url, count)) => (url, count),
            Err(e) => {
                warn!("Failed to publish to relays: {}", e);
                // Construct URL anyway for display using npub
                let url = format!("htree://{}/{}", self.nostr.npub(), &self.repo_name);
                (url, 0)
            }
        };

        // Print summary
        eprintln!("Published to: {} ({} relays, {} blossom servers)",
            npub_url, relay_count, blossom_count);

        Ok(())
    }

    /// Push content to file servers (blossom)
    /// Walks the merkle tree from root_hash and uploads blobs as it discovers them
    /// Returns the number of blossom servers successfully used
    fn push_to_file_servers(&self, root_hash: &str) -> usize {
        use hashtree_core::try_decode_tree_node;

        let store = self.storage.store();
        let blossom = self.nostr.blossom();
        let blossom_server_count = blossom.write_servers().len();

        // Create runtime for async uploads
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                warn!("Failed to create runtime for blossom upload: {}", e);
                return 0;
            }
        };

        // Parse root hash
        let root_bytes = match hex::decode(root_hash) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                warn!("Invalid root hash: {}", root_hash);
                return 0;
            }
        };

        let success = rt.block_on(async {
            let mut uploaded = 0usize;
            let mut skipped = 0usize;
            let mut failed = 0usize;
            let mut processed = 0usize;

            // Walk tree and upload as we go
            let mut visited: HashSet<[u8; 32]> = HashSet::new();
            let mut queue = vec![root_bytes];

            while let Some(hash) = queue.pop() {
                if visited.contains(&hash) {
                    continue;
                }
                visited.insert(hash);

                // Load blob from store
                let data = match store.get_sync(&hash) {
                    Ok(Some(data)) => data,
                    _ => {
                        failed += 1;
                        continue;
                    }
                };

                // Check if it's a tree node and queue children
                if let Some(node) = try_decode_tree_node(&data) {
                    for link in node.links {
                        if !visited.contains(&link.hash) {
                            queue.push(link.hash);
                        }
                    }
                }

                // Upload this blob
                match blossom.upload_if_missing(&data).await {
                    Ok((_, true)) => { uploaded += 1; }
                    Ok((_, false)) => { skipped += 1; }
                    Err(e) => {
                        debug!("Failed to upload blob {}: {}", hex::encode(&hash), e);
                        failed += 1;
                    }
                }

                processed += 1;
                if processed == 1 || processed % 10 == 0 {
                    eprint!("\r  Uploading: {} ({} new, {} exist)",
                        processed, uploaded, skipped);
                    let _ = std::io::stderr().flush();
                }
            }

            // Final progress
            eprint!("\r  Uploading: {} ({} new, {} exist)", processed, uploaded, skipped);
            eprintln!();

            info!(
                "Blossom upload complete: {} uploaded, {} already existed, {} failed",
                uploaded, skipped, failed
            );

            uploaded > 0 || skipped > 0
        });

        if success { blossom_server_count } else { 0 }
    }

    /// Collect all hashes reachable from a root hash by walking the merkle tree
    #[allow(dead_code)]
    fn collect_tree_hashes(&self, root_hash: &str) -> Result<Vec<[u8; 32]>> {
        use hashtree_core::try_decode_tree_node;

        let store = self.storage.store();
        let mut hashes = Vec::new();
        let mut visited: HashSet<[u8; 32]> = HashSet::new();

        // Parse root hash
        let root_bytes = hex::decode(root_hash)
            .context("Invalid root hash hex")?;
        if root_bytes.len() != 32 {
            bail!("Root hash must be 32 bytes");
        }
        let mut root: [u8; 32] = [0u8; 32];
        root.copy_from_slice(&root_bytes);

        let mut queue = vec![root];

        while let Some(hash) = queue.pop() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash);
            hashes.push(hash);

            // Get blob data and check if it's a tree node
            if let Ok(Some(data)) = store.get_sync(&hash) {
                // Try to decode as tree node
                if let Some(node) = try_decode_tree_node(&data) {
                    // Queue all child hashes
                    for link in node.links {
                        if !visited.contains(&link.hash) {
                            queue.push(link.hash);
                        }
                    }
                }
                // If not a tree node, it's a leaf blob - already added to hashes
            }
        }

        debug!("Collected {} hashes from tree {}", hashes.len(), &root_hash[..12]);
        Ok(hashes)
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

    /// Read multiple git objects using git cat-file --batch
    /// Processes in batches to avoid pipe buffer deadlock
    fn read_git_objects_batch(&self, oids: &[String]) -> Result<Vec<(ObjectType, Vec<u8>)>> {
        use std::io::{BufRead, BufReader, Read, Write};

        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let total = oids.len();
        let mut results = Vec::with_capacity(total);

        // Process in batches of 100 to avoid pipe buffer issues
        const BATCH_SIZE: usize = 100;

        for (batch_idx, batch) in oids.chunks(BATCH_SIZE).enumerate() {
            let mut child = Command::new("git")
                .args(["cat-file", "--batch"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?;

            let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("Failed to open stdin"))?;
            let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("Failed to open stdout"))?;

            // Write batch OIDs to stdin
            for oid in batch {
                writeln!(stdin, "{}", oid)?;
            }
            drop(stdin);

            // Read responses
            let mut reader = BufReader::new(stdout);

            for (i, oid) in batch.iter().enumerate() {
                let mut header = String::new();
                reader.read_line(&mut header)?;
                let header = header.trim();

                let parts: Vec<&str> = header.split_whitespace().collect();
                if parts.len() < 3 {
                    bail!("Object not found or invalid header for {}: {}", oid, header);
                }

                let obj_type = match parts[1] {
                    "blob" => ObjectType::Blob,
                    "tree" => ObjectType::Tree,
                    "commit" => ObjectType::Commit,
                    "tag" => ObjectType::Tag,
                    _ => bail!("Unknown object type: {}", parts[1]),
                };

                let size: usize = parts[2].parse()?;
                let mut content = vec![0u8; size];
                reader.read_exact(&mut content)?;

                // Read trailing newline
                let mut newline = [0u8; 1];
                reader.read_exact(&mut newline)?;

                results.push((obj_type, content));

                // Progress indicator
                let done = batch_idx * BATCH_SIZE + i + 1;
                if done == 1 || done % 100 == 0 || done == total {
                    eprint!("\r  Reading objects: {}/{}", done, total);
                    let _ = std::io::stderr().flush();
                }
            }

            child.wait()?;
        }

        Ok(results)
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
