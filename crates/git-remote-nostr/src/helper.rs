//! Git remote helper protocol implementation
//!
//! Implements the stateless git remote helper protocol.
//! See: https://git-scm.com/docs/gitremote-helpers

use anyhow::{bail, Result};
use hashtree_git::object::ObjectType;
use hashtree_git::refs::Ref;
use hashtree_git::storage::GitStorage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

use crate::nostr_client::NostrClient;

/// Get the shared hashtree data directory
fn get_hashtree_data_dir() -> PathBuf {
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
    pub fn new(pubkey: &str, repo_name: &str) -> Result<Self> {
        // Use shared hashtree storage at ~/.hashtree/data
        let storage = GitStorage::open(get_hashtree_data_dir())?;
        let nostr = NostrClient::new(pubkey)?;

        Ok(Self {
            pubkey: pubkey.to_string(),
            repo_name: repo_name.to_string(),
            storage,
            nostr,
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

        for spec in &self.fetch_specs {
            debug!("Fetching {} ({})", spec.name, spec.sha);

            // Fetch objects from nostr/blossom
            let objects = self.nostr.fetch_objects(&self.repo_name, &spec.sha)?;

            // Store in local git
            for (oid, data) in objects {
                self.write_git_object(&oid, &data)?;
            }
        }

        self.fetch_specs.clear();
        Ok(())
    }

    /// Write object to local git object store
    fn write_git_object(&self, oid: &str, data: &[u8]) -> Result<()> {
        // Use git hash-object to store
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(data)?;
        }

        let output = child.wait_with_output()?;
        let computed_oid = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if computed_oid != oid {
            warn!("OID mismatch: expected {}, got {}", oid, computed_oid);
        }

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

        // Update ref in storage using hashtree-git's Ref type
        let oid = hashtree_git::object::ObjectId::from_hex(sha)
            .ok_or_else(|| anyhow::anyhow!("Invalid object id: {}", sha))?;
        self.storage.write_ref(dst_ref, &Ref::Direct(oid))?;

        // Build the merkle tree
        let root_hash = self.storage.get_root_hash()?;

        // Publish to nostr (kind 30078 with hashtree label)
        self.nostr.publish_repo(&self.repo_name, &root_hash)?;

        Ok(())
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

    #[test]
    fn test_capabilities() {
        // Skip test if we can't create storage (no ~/.hashtree/data)
        let helper = match RemoteHelper::new(
            "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0",
            "test",
        ) {
            Ok(h) => h,
            Err(_) => return, // Skip if storage can't be created
        };

        let caps = helper.capabilities();
        assert!(caps.contains(&"fetch".to_string()));
        assert!(caps.contains(&"push".to_string()));
    }
}
