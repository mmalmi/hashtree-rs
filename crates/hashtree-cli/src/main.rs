//! Hashtree CLI and daemon
//!
//! Usage:
//!   htree start [--addr 127.0.0.1:8080]
//!   htree add <path> [--only-hash] [--public] [--no-ignore] [--publish <ref_name>]
//!   htree get <cid> [-o output]
//!   htree cat <cid>
//!   htree pins
//!   htree pin <cid>
//!   htree unpin <cid>
//!   htree info <cid>
//!   htree stats
//!   htree gc
//!   htree publish <ref_name> <hash> [--key <key>]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hashtree_cli::config::{ensure_auth_cookie, ensure_nsec, ensure_nsec_string, parse_npub, pubkey_bytes};
use hashtree_cli::{
    init_nostrdb_at, spawn_relay_thread, Config, GitStorage, HashtreeServer, HashtreeStore,
    NostrKeys, NostrResolverConfig, NostrRootResolver, NostrToBech32, RelayConfig, RootResolver,
};
use nostr::nips::nip19::ToBech32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "htree")]
#[command(about = "Content-addressed storage with Scionic Merkle Trees", long_about = None)]
struct Cli {
    #[arg(long, default_value = "./hashtree-data", global = true)]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the hashtree daemon
    Start {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// Add file or directory to hashtree (like ipfs add)
    Add {
        /// Path to file or directory
        path: PathBuf,
        /// Only compute hash, don't store
        #[arg(long)]
        only_hash: bool,
        /// Store without encryption (public, unencrypted)
        #[arg(long)]
        public: bool,
        /// Include files ignored by .gitignore (default: respect .gitignore)
        #[arg(long)]
        no_ignore: bool,
        /// Publish to Nostr under this ref name (e.g., "mydata" -> npub.../mydata)
        #[arg(long)]
        publish: Option<String>,
    },
    /// Get/download content by CID
    Get {
        /// CID to retrieve
        cid: String,
        /// Output path (default: current dir, uses CID as filename)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Output file content to stdout (like cat)
    Cat {
        /// CID to read
        cid: String,
    },
    /// List all pinned CIDs
    Pins,
    /// Pin a CID
    Pin {
        /// CID to pin
        cid: String,
    },
    /// Unpin a CID
    Unpin {
        /// CID to unpin
        cid: String,
    },
    /// Get information about a CID
    Info {
        /// CID to inspect
        cid: String,
    },
    /// Get storage statistics
    Stats,
    /// Run garbage collection
    Gc,
    /// Publish a hash to Nostr under a ref name
    Publish {
        /// The ref name to publish under (e.g., "mydata" -> npub.../mydata)
        ref_name: String,
        /// The hash to publish (hex encoded)
        hash: String,
        /// Optional decryption key (hex encoded, for encrypted content)
        #[arg(long)]
        key: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { addr } => {
            // Load or create config
            let config = Config::load()?;

            // Use data dir from config if not overridden by CLI
            let data_dir = if cli.data_dir.to_str() == Some("./hashtree-data") {
                PathBuf::from(&config.storage.data_dir)
            } else {
                cli.data_dir.clone()
            };

            let store = Arc::new(HashtreeStore::new(&data_dir)?);

            // Initialize nostrdb for event storage
            let nostrdb_path = data_dir.join("nostrdb");
            let ndb = init_nostrdb_at(&nostrdb_path)
                .context("Failed to initialize nostrdb")?;

            // Ensure nsec exists (generate if needed)
            let (keys, was_generated) = ensure_nsec()?;
            let pk_bytes = pubkey_bytes(&keys);
            let npub = keys.public_key().to_bech32()
                .context("Failed to encode npub")?;

            // Determine social graph root (from config or local nsec)
            let (root_pubkey, root_npub) = if let Some(ref npub_str) = config.nostr.socialgraph_root {
                let root_pk = parse_npub(npub_str)
                    .context("Invalid socialgraph_root npub in config")?;
                (root_pk, npub_str.clone())
            } else {
                (pk_bytes, npub.clone())
            };

            // Set social graph root
            nostrdb::socialgraph::set_root(&ndb, &root_pubkey);

            // Start relay connections (outbound)
            // Crawl social graph starting from root user
            let relay_config = RelayConfig {
                relays: config.nostr.relays.clone(),
                authors: vec![pk_bytes], // Subscribe to own events
                root_pubkey: Some(root_pubkey),
                crawl_seeds: if config.nostr.crawl_depth > 0 { vec![root_pubkey] } else { vec![] },
                crawl_depth: config.nostr.crawl_depth,
                ..Default::default()
            };
            let relay_handle = spawn_relay_thread(ndb.clone(), relay_config);

            // Initialize git storage at shared data directory
            let git_storage = Arc::new(GitStorage::open(&data_dir)
                .context("Failed to initialize git storage")?);

            // Start STUN server if configured
            let stun_handle = if config.server.stun_port > 0 {
                let stun_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.server.stun_port)
                    .parse()
                    .context("Invalid STUN bind address")?;
                Some(hashtree_cli::server::stun::start_stun_server(stun_addr).await
                    .context("Failed to start STUN server")?)
            } else {
                None
            };

            // WebRTC is not yet fully supported in the daemon (enostr RelayPool is not Send)
            // WebRTC config is in config.server.enable_webrtc

            // Set up server with nostr relay (inbound) and query sender
            let mut server = HashtreeServer::new(store, addr.clone())
                .with_ndb(ndb)
                .with_ndb_query(relay_handle.query.clone())
                .with_max_write_distance(config.nostr.max_write_distance)
                .with_git(git_storage, hex::encode(pk_bytes));

            // Print startup info
            println!("Starting hashtree daemon on {}", addr);
            println!("Data directory: {}", data_dir.display());
            println!("Nostrdb: {}", nostrdb_path.display());
            if was_generated {
                println!("Identity: {} (new)", npub);
            } else {
                println!("Identity: {}", npub);
            }
            if root_npub != npub {
                println!("Social graph root: {}", root_npub);
            }
            if config.nostr.crawl_depth > 0 {
                println!("Crawl depth: {}", config.nostr.crawl_depth);
            }
            if let Some(max_dist) = config.nostr.max_write_distance {
                println!("Write access: social graph distance <= {}", max_dist);
            }
            println!("Relays: {} configured", config.nostr.relays.len());
            println!("Nostr relay: ws://{}", addr);
            println!("Git remote: http://{}/git/<pubkey>/<repo>", addr);
            if let Some(ref handle) = stun_handle {
                println!("STUN server: {}", handle.addr);
            }
            if config.server.enable_webrtc {
                println!("WebRTC: enabled (P2P connections)");
            }

            if config.server.enable_auth {
                let (username, password) = ensure_auth_cookie()?;
                println!();
                println!("Web UI: http://{}/#{}:{}", addr, username, password);
                server = server.with_auth(username, password);
            } else {
                println!("Web UI: http://{}", addr);
                println!("Auth: disabled");
            }

            server.run().await?;

            // Shutdown STUN server
            if let Some(handle) = stun_handle {
                handle.shutdown();
            }

            // Shutdown relay thread
            relay_handle.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Commands::Add { path, only_hash, public, no_ignore, publish } => {
            let is_dir = path.is_dir();

            if only_hash {
                // Use in-memory store for hash-only mode
                use hashtree::store::MemoryStore;
                use hashtree::{HashTree, HashTreeConfig, to_hex};
                use std::sync::Arc;

                let store = Arc::new(MemoryStore::new());
                // Use unified API: encryption by default, .public() to disable
                let config = if public {
                    HashTreeConfig::new(store.clone()).public()
                } else {
                    HashTreeConfig::new(store.clone())
                };
                let tree = HashTree::new(config);

                if is_dir {
                    // For directories, use the recursive helper
                    let cid = add_directory(&tree, &path, !no_ignore).await?;
                    println!("hash: {}", to_hex(&cid.hash));
                    if let Some(key) = cid.key {
                        println!("key:  {}", to_hex(&key));
                    }
                } else {
                    let data = std::fs::read(&path)?;
                    let cid = tree.put(&data).await
                        .map_err(|e| anyhow::anyhow!("Failed to hash file: {}", e))?;
                    println!("hash: {}", to_hex(&cid.hash));
                    if let Some(key) = cid.key {
                        println!("key:  {}", to_hex(&key));
                    }
                }
            } else {
                // Store in local hashtree
                use hashtree::{nhash_encode, nhash_encode_full, NHashData, from_hex, key_from_hex, Cid};

                let store = HashtreeStore::new(&cli.data_dir)?;

                // Store and capture hash/key for potential publishing
                let (hash_hex, key_hex): (String, Option<String>) = if public {
                    let hash_hex = if is_dir {
                        store.upload_dir_with_options(&path, !no_ignore)
                            .context("Failed to add directory")?
                    } else {
                        store.upload_file(&path)
                            .context("Failed to add file")?
                    };
                    let hash = from_hex(&hash_hex).context("Invalid hash")?;
                    let nhash = nhash_encode(&hash)
                        .map_err(|e| anyhow::anyhow!("Failed to encode nhash: {}", e))?;
                    println!("added {}", path.display());
                    println!("  nhash: {}", nhash);
                    println!("  hash:  {}", hash_hex);
                    (hash_hex, None)
                } else {
                    let cid_str = if is_dir {
                        store.upload_dir_encrypted_with_options(&path, !no_ignore)
                            .context("Failed to add directory")?
                    } else {
                        store.upload_file_encrypted(&path)
                            .context("Failed to add file")?
                    };
                    // Parse cid_str which may be "hash" or "hash:key"
                    let (hash_hex, key_hex) = if let Some((h, k)) = cid_str.split_once(':') {
                        (h.to_string(), Some(k.to_string()))
                    } else {
                        (cid_str.clone(), None)
                    };
                    let hash = from_hex(&hash_hex).context("Invalid hash")?;
                    let key = key_hex.as_ref().map(|k| key_from_hex(k)).transpose()
                        .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
                    let nhash_data = NHashData {
                        hash,
                        path: vec![],
                        decrypt_key: key,
                    };
                    let nhash = nhash_encode_full(&nhash_data)
                        .map_err(|e| anyhow::anyhow!("Failed to encode nhash: {}", e))?;
                    println!("added {}", path.display());
                    println!("  nhash: {}", nhash);
                    println!("  hash:  {}", hash_hex);
                    if let Some(ref k) = key_hex {
                        println!("  key:   {}", k);
                    }
                    (hash_hex, key_hex)
                };

                // Publish to Nostr if --publish was specified
                if let Some(ref_name) = publish {
                    // Load config for relay list
                    let config = Config::load()?;

                    // Ensure nsec exists (generate if needed)
                    let (nsec_str, was_generated) = ensure_nsec_string()?;

                    // Create Keys using nostr-sdk's version (via NostrKeys re-export)
                    let keys = NostrKeys::parse(&nsec_str)
                        .context("Failed to parse nsec")?;
                    let npub = NostrToBech32::to_bech32(&keys.public_key())
                        .context("Failed to encode npub")?;

                    if was_generated {
                        println!("  identity: {} (new)", npub);
                    }

                    // Create resolver config with secret key for publishing
                    let resolver_config = NostrResolverConfig {
                        relays: config.nostr.relays.clone(),
                        resolve_timeout: Duration::from_secs(5),
                        secret_key: Some(keys),
                    };

                    // Create resolver
                    let resolver = NostrRootResolver::new(resolver_config).await
                        .context("Failed to create Nostr resolver")?;

                    // Build Cid from computed hash
                    let hash = from_hex(&hash_hex).context("Invalid hash")?;
                    let key = key_hex.as_ref().map(|k| key_from_hex(k)).transpose()
                        .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;
                    let cid = Cid { hash, key, size: 0 };

                    // Build Nostr key: "npub.../ref_name"
                    let nostr_key = format!("{}/{}", npub, ref_name);

                    // Publish
                    match resolver.publish(&nostr_key, &cid).await {
                        Ok(_) => {
                            println!("  published: {}", nostr_key);
                        }
                        Err(e) => {
                            eprintln!("  publish failed: {}", e);
                        }
                    }

                    // Clean up
                    let _ = resolver.stop().await;
                }
            }
        }
        Commands::Get { cid, output } => {
            let store = HashtreeStore::new(&cli.data_dir)?;

            // Check if it's a directory
            if let Ok(Some(_)) = store.get_directory_listing(&cid) {
                // It's a directory - create it and download contents
                let out_dir = output.unwrap_or_else(|| PathBuf::from(&cid));
                std::fs::create_dir_all(&out_dir)?;

                fn download_dir(store: &HashtreeStore, cid: &str, dir: &std::path::Path) -> Result<()> {
                    if let Some(listing) = store.get_directory_listing(cid)? {
                        for entry in listing.entries {
                            let entry_path = dir.join(&entry.name);
                            if entry.is_directory {
                                std::fs::create_dir_all(&entry_path)?;
                                download_dir(store, &entry.cid, &entry_path)?;
                            } else if let Some(content) = store.get_file(&entry.cid)? {
                                std::fs::write(&entry_path, content)?;
                                println!("  {} -> {}", entry.cid, entry_path.display());
                            }
                        }
                    }
                    Ok(())
                }

                println!("Downloading directory to {}", out_dir.display());
                download_dir(&store, &cid, &out_dir)?;
                println!("Done.");
            } else if let Some(content) = store.get_file(&cid)? {
                // It's a file
                let out_path = output.unwrap_or_else(|| PathBuf::from(&cid));
                std::fs::write(&out_path, content)?;
                println!("{} -> {}", cid, out_path.display());
            } else {
                anyhow::bail!("CID not found: {}", cid);
            }
        }
        Commands::Cat { cid } => {
            let store = HashtreeStore::new(&cli.data_dir)?;

            if let Some(content) = store.get_file(&cid)? {
                use std::io::Write;
                std::io::stdout().write_all(&content)?;
            } else {
                anyhow::bail!("CID not found: {}", cid);
            }
        }
        Commands::Pins => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            let pins = store.list_pins_with_names()?;
            if pins.is_empty() {
                println!("No pinned CIDs");
            } else {
                println!("Pinned items ({}):", pins.len());
                for pin in pins {
                    let icon = if pin.is_directory { "dir" } else { "file" };
                    println!("  [{}] {} ({})", icon, pin.name, pin.cid);
                }
            }
        }
        Commands::Pin { cid } => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            store.pin(&cid)?;
            println!("Pinned: {}", cid);
        }
        Commands::Unpin { cid } => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            store.unpin(&cid)?;
            println!("Unpinned: {}", cid);
        }
        Commands::Info { cid } => {
            let store = HashtreeStore::new(&cli.data_dir)?;

            // Check if content exists using file chunk metadata
            if let Some(metadata) = store.get_file_chunk_metadata(&cid)? {
                println!("Hash: {}", cid);
                println!("Pinned: {}", store.is_pinned(&cid)?);
                println!("Total size: {} bytes", metadata.total_size);
                println!("Chunked: {}", metadata.is_chunked);

                if metadata.is_chunked {
                    println!("Chunks: {}", metadata.chunk_cids.len());
                    println!("\nChunk details:");
                    for (i, (chunk_cid, size)) in metadata.chunk_cids.iter().zip(metadata.chunk_sizes.iter()).enumerate() {
                        println!("  [{}] {} ({} bytes)", i, chunk_cid, size);
                    }
                }

                // Show directory listing if it's a directory
                if let Ok(Some(listing)) = store.get_directory_listing(&cid) {
                    println!("\nDirectory contents:");
                    for entry in listing.entries {
                        let type_str = if entry.is_directory { "dir" } else { "file" };
                        println!("  [{}] {} -> {} ({} bytes)",
                            type_str, entry.name, entry.cid, entry.size);
                    }
                }

                // Show tree node info if available
                if let Ok(Some(node)) = store.get_tree_node(&cid) {
                    println!("\nTree node info:");
                    println!("  Links: {}", node.links.len());
                    if let Some(total_size) = node.total_size {
                        println!("  Stored total_size: {}", total_size);
                    }
                    for (i, link) in node.links.iter().enumerate() {
                        let name = link.name.as_ref().map(|n| n.as_str()).unwrap_or("<unnamed>");
                        let size_str = link.size.map(|s| format!("{} bytes", s)).unwrap_or_else(|| "?".to_string());
                        println!("    [{}] {} -> {} ({})", i, name, hashtree::to_hex(&link.hash), size_str);
                    }
                }
            } else {
                println!("Hash not found: {}", cid);
            }
        }
        Commands::Stats => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            let stats = store.get_storage_stats()?;
            println!("Storage Statistics:");
            println!("  Total DAGs: {}", stats.total_dags);
            println!("  Pinned DAGs: {}", stats.pinned_dags);
            println!("  Total size: {} bytes ({:.2} KB)",
                stats.total_bytes,
                stats.total_bytes as f64 / 1024.0);
        }
        Commands::Gc => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            println!("Running garbage collection...");
            let gc_stats = store.gc()?;
            println!("Deleted {} DAGs", gc_stats.deleted_dags);
            println!("Freed {} bytes ({:.2} KB)",
                gc_stats.freed_bytes,
                gc_stats.freed_bytes as f64 / 1024.0);
        }
        Commands::Publish { ref_name, hash, key } => {
            use hashtree::{from_hex, key_from_hex, Cid};

            // Load config for relay list
            let config = Config::load()?;

            // Ensure nsec exists (generate if needed)
            let (nsec_str, was_generated) = ensure_nsec_string()?;

            // Create Keys using nostr-sdk's version
            let keys = NostrKeys::parse(&nsec_str)
                .context("Failed to parse nsec")?;
            let npub = NostrToBech32::to_bech32(&keys.public_key())
                .context("Failed to encode npub")?;

            if was_generated {
                println!("Identity: {} (new)", npub);
            }

            // Parse hash and optional key
            let hash_bytes = from_hex(&hash)
                .context("Invalid hash (expected hex)")?;
            let key_bytes = key.as_ref()
                .map(|k| key_from_hex(k))
                .transpose()
                .map_err(|e| anyhow::anyhow!("Invalid key: {}", e))?;

            let cid = Cid {
                hash: hash_bytes,
                key: key_bytes,
                size: 0,
            };

            // Create resolver config with secret key for publishing
            let resolver_config = NostrResolverConfig {
                relays: config.nostr.relays.clone(),
                resolve_timeout: Duration::from_secs(5),
                secret_key: Some(keys),
            };

            // Create resolver
            let resolver = NostrRootResolver::new(resolver_config).await
                .context("Failed to create Nostr resolver")?;

            // Build Nostr key: "npub.../ref_name"
            let nostr_key = format!("{}/{}", npub, ref_name);

            // Publish
            match resolver.publish(&nostr_key, &cid).await {
                Ok(_) => {
                    println!("Published: {}", nostr_key);
                    println!("  hash: {}", hash);
                    if let Some(k) = key {
                        println!("  key:  {}", k);
                    }
                }
                Err(e) => {
                    eprintln!("Publish failed: {}", e);
                    std::process::exit(1);
                }
            }

            // Clean up
            let _ = resolver.stop().await;
        }
    }

    Ok(())
}

/// Recursively add a directory (handles encryption automatically based on tree config)
async fn add_directory<S: hashtree::store::Store>(
    tree: &hashtree::HashTree<S>,
    dir: &std::path::Path,
    respect_gitignore: bool,
) -> Result<hashtree::Cid> {
    use ignore::WalkBuilder;
    use hashtree::DirEntry;
    use std::collections::HashMap;

    // Collect files by their parent directory path
    let mut dir_contents: HashMap<String, Vec<(String, hashtree::Cid)>> = HashMap::new();

    // Use ignore crate for gitignore-aware walking
    let walker = WalkBuilder::new(dir)
        .git_ignore(respect_gitignore)
        .git_global(respect_gitignore)
        .git_exclude(respect_gitignore)
        .hidden(false)
        .build();

    for result in walker {
        let entry = result?;
        let path = entry.path();

        // Skip the root directory itself
        if path == dir {
            continue;
        }

        let relative = path.strip_prefix(dir).unwrap_or(path);

        if path.is_file() {
            let data = std::fs::read(path)?;
            let cid = tree.put(&data).await
                .map_err(|e| anyhow::anyhow!("Failed to add file {}: {}", path.display(), e))?;

            let parent = relative.parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let name = relative.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            dir_contents.entry(parent).or_default().push((name, cid));
        } else if path.is_dir() {
            // Ensure directory entry exists
            let dir_path = relative.to_string_lossy().to_string();
            dir_contents.entry(dir_path).or_default();
        }
    }

    // Build directory tree bottom-up
    let mut dirs: Vec<String> = dir_contents.keys().cloned().collect();
    dirs.sort_by(|a, b| {
        let depth_a = a.matches('/').count() + if a.is_empty() { 0 } else { 1 };
        let depth_b = b.matches('/').count() + if b.is_empty() { 0 } else { 1 };
        depth_b.cmp(&depth_a) // Deepest first
    });

    let mut dir_cids: HashMap<String, hashtree::Cid> = HashMap::new();

    for dir_path in dirs {
        let files = dir_contents.get(&dir_path).cloned().unwrap_or_default();

        let mut entries: Vec<DirEntry> = files.into_iter()
            .map(|(name, cid)| DirEntry::from_cid(name, &cid))
            .collect();

        // Add subdirectory entries
        for (subdir_path, cid) in &dir_cids {
            let parent = std::path::Path::new(subdir_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if parent == dir_path {
                let name = std::path::Path::new(subdir_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                entries.push(DirEntry::from_cid(name, cid));
            }
        }

        let cid = tree.put_directory(entries, None).await
            .map_err(|e| anyhow::anyhow!("Failed to create directory node: {}", e))?;

        dir_cids.insert(dir_path, cid);
    }

    // Return root directory cid
    dir_cids.get("")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No root directory"))
}

/// Calculate total size of a directory
#[allow(dead_code)]
fn dir_size(path: &std::path::Path) -> Result<u64> {
    let mut size = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            size += dir_size(&path)?;
        } else {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}
