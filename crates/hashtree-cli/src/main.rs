//! Hashtree CLI and daemon
//!
//! Usage:
//!   htree start [--addr 127.0.0.1:8080] [--webrtc]
//!   htree upload <file>
//!   htree upload-dir <dir>
//!   htree pins
//!   htree pin <cid>
//!   htree unpin <cid>
//!   htree info <cid>
//!   htree stats
//!   htree gc

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hashtree_cli::config::{ensure_auth_cookie, ensure_nsec, parse_npub, pubkey_bytes};
use hashtree_cli::{init_nostrdb_at, spawn_relay_thread, Config, GitStorage, HashtreeServer, HashtreeStore, RelayConfig};
use nostr::nips::nip19::ToBech32;
use std::path::PathBuf;
use std::sync::Arc;

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
        /// Enable WebRTC P2P connections
        #[arg(long)]
        webrtc: bool,
    },
    /// Upload a file and get its CID
    Upload {
        /// Path to the file to upload
        file: PathBuf,
    },
    /// Upload a directory and get its CID
    UploadDir {
        /// Path to the directory to upload
        dir: PathBuf,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { addr, webrtc } => {
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

            // WebRTC is not yet supported in the daemon (enostr RelayPool is not Send)
            // Use the standalone webrtc-test binary for testing
            let _ = webrtc;

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
            if webrtc {
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
        Commands::Upload { file } => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            let cid = store.upload_file(&file)
                .context("Failed to upload file")?;
            println!("Uploaded: {}", file.display());
            println!("CID: {}", cid);
            println!("Retrieve: http://127.0.0.1:8080/{}", cid);
        }
        Commands::UploadDir { dir } => {
            let store = HashtreeStore::new(&cli.data_dir)?;
            let cid = store.upload_dir(&dir)
                .context("Failed to upload directory")?;
            println!("Uploaded directory: {}", dir.display());
            println!("CID: {}", cid);
            println!("Retrieve: http://127.0.0.1:8080/{}", cid);
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
    }

    Ok(())
}
