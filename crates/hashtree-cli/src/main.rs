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
//!   htree user [<nsec>]
//!   htree publish <ref_name> <hash> [--key <key>]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hashtree_cli::config::{ensure_auth_cookie, ensure_nsec, ensure_nsec_string, parse_npub, pubkey_bytes};
use hashtree_cli::{
    init_nostrdb_at, spawn_relay_thread, Config, GitStorage, HashtreeServer, HashtreeStore,
    NostrKeys, NostrResolverConfig, NostrRootResolver, NostrToBech32, PeerPool, RelayConfig, RootResolver,
    WebRTCConfig, WebRTCManager,
};
use nostr::nips::nip19::ToBech32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "htree")]
#[command(about = "Content-addressed storage with Scionic Merkle Trees", long_about = None)]
struct Cli {
    #[arg(long, default_value = "./hashtree-data", global = true, env = "HTREE_DATA_DIR")]
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
    /// Show or set your nostr identity
    User {
        /// npub or nsec to set as active identity (omit to show current)
        identity: Option<String>,
    },
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
    /// Follow a user (adds to your contact list)
    Follow {
        /// npub of user to follow
        npub: String,
    },
    /// Unfollow a user (removes from your contact list)
    Unfollow {
        /// npub of user to unfollow
        npub: String,
    },
    /// List users you follow
    Following,
    /// Push content to Blossom servers
    Push {
        /// CID (hash or hash:key) to push
        cid: String,
        /// Blossom server URL (overrides config)
        #[arg(long, short)]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing (respects RUST_LOG env var)
    tracing_subscriber::fmt::init();

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

            // Start WebRTC signaling manager if enabled
            let (webrtc_handle, webrtc_state) = if config.server.enable_webrtc {
                let webrtc_config = WebRTCConfig {
                    relays: config.nostr.relays.clone(),
                    ..Default::default()
                };

                // Create peer classifier based on social graph
                // Distance 0 = self, 1 = direct follow/follower -> Follows pool
                // Distance > 1 or unknown -> Other pool
                let ndb_for_classifier = ndb.clone();
                let contacts_file = data_dir.join("contacts.json");
                let peer_classifier: hashtree_cli::PeerClassifier = Arc::new(move |pubkey_hex: &str| {
                    // First check local contacts.json file (updated by htree follow command)
                    if contacts_file.exists() {
                        if let Ok(data) = std::fs::read_to_string(&contacts_file) {
                            if let Ok(contacts) = serde_json::from_str::<Vec<String>>(&data) {
                                if contacts.contains(&pubkey_hex.to_string()) {
                                    return PeerPool::Follows;
                                }
                            }
                        }
                    }

                    // Fall back to nostrdb social graph
                    if let Ok(pubkey_bytes) = hex::decode(pubkey_hex) {
                        if pubkey_bytes.len() == 32 {
                            let pk: [u8; 32] = pubkey_bytes.try_into().unwrap();
                            if let Ok(txn) = nostrdb::Transaction::new(&ndb_for_classifier) {
                                let distance = nostrdb::socialgraph::get_follow_distance(&txn, &ndb_for_classifier, &pk);
                                // Distance 0 = self (skip), 1 = direct follow/follower
                                if distance == 1 {
                                    return PeerPool::Follows;
                                }
                            }
                        }
                    }
                    PeerPool::Other
                });

                let mut manager = WebRTCManager::new_with_store_and_classifier(
                    keys.clone(),
                    webrtc_config,
                    Arc::clone(&store) as Arc<dyn hashtree_cli::ContentStore>,
                    peer_classifier,
                );

                // Get the WebRTC state before spawning (for HTTP handler to query peers)
                let webrtc_state = manager.state();

                // Spawn the manager in a background task
                let handle = tokio::spawn(async move {
                    if let Err(e) = manager.run().await {
                        tracing::error!("WebRTC manager error: {}", e);
                    }
                });
                (Some(handle), Some(webrtc_state))
            } else {
                (None, None)
            };

            // Set up server with nostr relay (inbound) and query sender
            let mut server = HashtreeServer::new(store, addr.clone())
                .with_ndb(ndb)
                .with_ndb_query(relay_handle.query.clone())
                .with_max_write_distance(config.nostr.max_write_distance)
                .with_git(git_storage, hex::encode(pk_bytes));

            // Add WebRTC peer state for P2P queries from HTTP handler
            if let Some(webrtc_state) = webrtc_state {
                server = server.with_webrtc_peers(webrtc_state);
            }

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

            // Shutdown WebRTC manager
            if let Some(handle) = webrtc_handle {
                handle.abort();
            }

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
                    for (i, link) in node.links.iter().enumerate() {
                        let name = link.name.as_ref().map(|n| n.as_str()).unwrap_or("<unnamed>");
                        let size_str = format!("{} bytes", link.size);
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
        Commands::User { identity } => {
            use hashtree_cli::config::get_nsec_path;
            use nostr::nips::nip19::FromBech32;
            use std::fs;

            match identity {
                None => {
                    // Show current identity
                    let (keys, was_generated) = ensure_nsec()?;
                    let npub = keys.public_key().to_bech32()?;
                    if was_generated {
                        eprintln!("Generated new identity");
                    }
                    println!("{}", npub);
                }
                Some(id) => {
                    // Set identity - accept nsec or derive from input
                    let nsec = if id.starts_with("nsec1") {
                        // Validate it's a valid nsec
                        nostr::SecretKey::from_bech32(&id)
                            .context("Invalid nsec")?;
                        id
                    } else {
                        anyhow::bail!("Identity must be an nsec (secret key). Use 'htree user' to see your current npub.");
                    };

                    // Save to nsec file
                    let nsec_path = get_nsec_path();
                    if let Some(parent) = nsec_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&nsec_path, &nsec)?;

                    // Set permissions to 0600
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&nsec_path, fs::Permissions::from_mode(0o600))?;
                    }

                    // Show the new npub
                    let secret_key = nostr::SecretKey::from_bech32(&nsec)?;
                    let keys = nostr::Keys::new(secret_key);
                    let npub = keys.public_key().to_bech32()?;
                    println!("{}", npub);
                }
            }
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
        Commands::Follow { npub } => {
            follow_user(&cli.data_dir, &npub, true).await?;
        }
        Commands::Unfollow { npub } => {
            follow_user(&cli.data_dir, &npub, false).await?;
        }
        Commands::Following => {
            list_following(&cli.data_dir).await?;
        }
        Commands::Push { cid, server } => {
            push_to_blossom(&cli.data_dir, &cid, server).await?;
        }
    }

    Ok(())
}

/// Follow or unfollow a user by publishing an updated kind 3 contact list
async fn follow_user(data_dir: &PathBuf, npub_str: &str, follow: bool) -> Result<()> {
    use nostr::{EventBuilder, Kind, Tag, PublicKey, Keys, JsonUtil, ClientMessage};
    use tokio_tungstenite::connect_async;
    use futures::sink::SinkExt;

    // Load config for relay list
    let config = Config::load()?;

    // Ensure nsec exists
    let (nsec_str, _) = ensure_nsec_string()?;
    let keys = Keys::parse(&nsec_str).context("Failed to parse nsec")?;

    // Parse target npub
    let target_pubkey = parse_npub(npub_str).context("Invalid npub")?;
    let target_pubkey_hex = hex::encode(target_pubkey);

    // Load existing contact list from local storage
    let contacts_file = data_dir.join("contacts.json");
    let mut contacts: Vec<String> = if contacts_file.exists() {
        let data = std::fs::read_to_string(&contacts_file)?;
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Update contacts
    if follow {
        if !contacts.contains(&target_pubkey_hex) {
            contacts.push(target_pubkey_hex.clone());
            println!("Following: {}", npub_str);
        } else {
            println!("Already following: {}", npub_str);
            return Ok(());
        }
    } else {
        if let Some(pos) = contacts.iter().position(|x| x == &target_pubkey_hex) {
            contacts.remove(pos);
            println!("Unfollowed: {}", npub_str);
        } else {
            println!("Not following: {}", npub_str);
            return Ok(());
        }
    }

    // Save updated contacts locally
    std::fs::write(&contacts_file, serde_json::to_string_pretty(&contacts)?)?;

    // Build kind 3 contact list event
    let tags: Vec<Tag> = contacts.iter()
        .filter_map(|pk_hex| {
            PublicKey::from_hex(pk_hex).ok().map(|pk| Tag::public_key(pk))
        })
        .collect();

    let event = EventBuilder::new(Kind::ContactList, "")
        .tags(tags)
        .sign(&keys)
        .await
        .context("Failed to sign contact list event")?;

    let event_json = ClientMessage::event(event).as_json();

    // Publish to relays
    let mut success_count = 0;
    for relay in &config.nostr.relays {
        match connect_async(relay).await {
            Ok((mut ws, _)) => {
                if ws.send(tokio_tungstenite::tungstenite::Message::Text(event_json.clone().into())).await.is_ok() {
                    success_count += 1;
                }
                let _ = ws.close(None).await;
            }
            Err(_) => {}
        }
    }

    println!("Published contact list to {} relays", success_count);
    Ok(())
}

/// List users we follow
async fn list_following(data_dir: &PathBuf) -> Result<()> {
    use nostr::PublicKey;
    use nostr::nips::nip19::ToBech32;

    // Load contacts from local storage
    let contacts_file = data_dir.join("contacts.json");
    let contacts: Vec<String> = if contacts_file.exists() {
        let data = std::fs::read_to_string(&contacts_file)?;
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    };

    if contacts.is_empty() {
        println!("Not following anyone");
        return Ok(());
    }

    println!("Following {} users:", contacts.len());
    for pk_hex in &contacts {
        if let Ok(pk) = PublicKey::from_hex(pk_hex) {
            if let Ok(npub) = pk.to_bech32() {
                println!("  {}", npub);
            } else {
                println!("  {}", pk_hex);
            }
        } else {
            println!("  {} (invalid)", pk_hex);
        }
    }

    Ok(())
}

/// Push content to Blossom servers
async fn push_to_blossom(data_dir: &PathBuf, cid_str: &str, server_override: Option<String>) -> Result<()> {
    use hashtree::{from_hex, to_hex};
    use sha2::{Sha256, Digest};
    use nostr::{EventBuilder, Kind, Tag, TagKind, Keys, JsonUtil};

    // Load config
    let config = Config::load()?;

    // Get servers (override or from config)
    let servers = if let Some(s) = server_override {
        vec![s]
    } else {
        config.blossom.servers.clone()
    };

    if servers.is_empty() {
        anyhow::bail!("No Blossom servers configured. Use --server or add servers to config.toml");
    }

    // Ensure nsec exists for signing
    let (nsec_str, _) = ensure_nsec_string()?;
    let keys = Keys::parse(&nsec_str).context("Failed to parse nsec")?;

    // Open local store
    let store = HashtreeStore::new(data_dir)?;

    // Parse CID (hash or hash:key)
    let (hash_hex, _key_hex) = if let Some((h, k)) = cid_str.split_once(':') {
        (h.to_string(), Some(k.to_string()))
    } else {
        (cid_str.to_string(), None)
    };

    let _root_hash = from_hex(&hash_hex).context("Invalid hash")?;

    // Collect all blocks to push (walk the DAG)
    println!("Collecting blocks...");
    let mut blocks_to_push: Vec<(String, Vec<u8>)> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![hash_hex.clone()];

    while let Some(hash) = queue.pop() {
        if visited.contains(&hash) {
            continue;
        }
        visited.insert(hash.clone());

        // Try to get as tree node first (for directories/internal nodes)
        if let Ok(Some(node)) = store.get_tree_node(&hash) {
            // Get raw block data
            if let Ok(Some(data)) = store.get_blob(&hash) {
                blocks_to_push.push((hash.clone(), data));
            }
            // Queue child hashes
            for link in &node.links {
                let child_hash = to_hex(&link.hash);
                if !visited.contains(&child_hash) {
                    queue.push(child_hash);
                }
            }
        } else if let Ok(Some(metadata)) = store.get_file_chunk_metadata(&hash) {
            // It's a file - get the file data
            if metadata.is_chunked {
                // Get chunks
                for chunk_cid in &metadata.chunk_cids {
                    if !visited.contains(chunk_cid) {
                        if let Ok(Some(chunk_data)) = store.get_blob(chunk_cid) {
                            blocks_to_push.push((chunk_cid.clone(), chunk_data));
                            visited.insert(chunk_cid.clone());
                        }
                    }
                }
            }
            // Get the file's own block
            if let Ok(Some(data)) = store.get_blob(&hash) {
                blocks_to_push.push((hash.clone(), data));
            }
        } else if let Ok(Some(data)) = store.get_blob(&hash) {
            // Raw block
            blocks_to_push.push((hash.clone(), data));
        }
    }

    println!("Found {} blocks to push", blocks_to_push.len());

    // Create HTTP client
    let client = reqwest::Client::new();

    // Push to each server
    for server in &servers {
        println!("\nPushing to {}...", server);
        let mut uploaded = 0;
        let mut skipped = 0;
        let mut errors = 0;

        for (hash, data) in &blocks_to_push {
            // Check if already exists (HEAD request)
            let url = format!("{}/{}.bin", server.trim_end_matches('/'), hash);
            let head_resp = client.head(&url).send().await;

            if let Ok(resp) = head_resp {
                if resp.status().is_success() || resp.status().as_u16() == 200 {
                    skipped += 1;
                    continue;
                }
            }

            // Create Blossom auth event (kind 24242)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expiration = now + 300; // 5 minutes

            // Compute SHA256 of the data
            let mut hasher = Sha256::new();
            hasher.update(data);
            let computed_hash = hex::encode(hasher.finalize());

            // Build auth event
            let auth_event = EventBuilder::new(
                Kind::Custom(24242),
                "Upload",
            )
            .tags(vec![
                Tag::custom(TagKind::custom("t"), vec!["upload".to_string()]),
                Tag::custom(TagKind::custom("x"), vec![computed_hash.clone()]),
                Tag::custom(TagKind::custom("expiration"), vec![expiration.to_string()]),
            ])
            .sign(&keys)
            .await
            .context("Failed to sign auth event")?;

            let auth_json = auth_event.as_json();
            let auth_header = format!("Nostr {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth_json));

            // Upload
            let upload_url = format!("{}/upload", server.trim_end_matches('/'));
            let resp = client.put(&upload_url)
                .header("Authorization", auth_header)
                .header("Content-Type", "application/octet-stream")
                .header("X-SHA-256", &computed_hash)
                .body(data.clone())
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() || r.status().as_u16() == 409 => {
                    uploaded += 1;
                }
                Ok(r) => {
                    let status = r.status();
                    let text = r.text().await.unwrap_or_default();
                    eprintln!("  Error uploading {}: {} {}", &hash[..12], status, text);
                    errors += 1;
                }
                Err(e) => {
                    eprintln!("  Error uploading {}: {}", &hash[..12], e);
                    errors += 1;
                }
            }
        }

        println!("  Uploaded: {}, Skipped: {}, Errors: {}", uploaded, skipped, errors);
    }

    println!("\nDone!");
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

        let cid = tree.put_directory(entries).await
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
