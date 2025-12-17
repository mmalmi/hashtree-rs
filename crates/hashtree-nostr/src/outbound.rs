//! Outbound relay connections - connecting to other relays
//!
//! Handles connecting to nostr relays and ingesting events into nostrdb.

use anyhow::Result;
use nostr_sdk::prelude::*;
use nostrdb::{FilterBuilder, Ndb, Transaction};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// Query types that can be sent to the ndb thread
pub enum NdbQuery {
    /// Get social graph stats for a pubkey
    SocialGraphStats {
        pubkey: [u8; 32],
        reply: mpsc::Sender<SocialGraphStats>,
    },
    /// Get social graph stats for the root user
    SocialGraphRootStats {
        reply: mpsc::Sender<SocialGraphStats>,
    },
}

/// Social graph statistics
#[derive(Debug, Clone, Default)]
pub struct SocialGraphStats {
    pub following_count: usize,
    pub followers_count: usize,
    pub follow_distance: u32,
}

/// Handle for sending queries to the ndb thread
#[derive(Clone)]
pub struct NdbQuerySender {
    tx: mpsc::Sender<NdbQuery>,
}

impl NdbQuerySender {
    /// Query social graph stats for a pubkey
    pub fn socialgraph_stats(&self, pubkey: [u8; 32]) -> Result<SocialGraphStats> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(NdbQuery::SocialGraphStats { pubkey, reply: reply_tx })?;
        Ok(reply_rx.recv()?)
    }

    /// Query social graph stats for the root user
    pub fn socialgraph_root_stats(&self) -> Result<SocialGraphStats> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(NdbQuery::SocialGraphRootStats { reply: reply_tx })?;
        Ok(reply_rx.recv()?)
    }
}

/// Default relays to connect to
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://temp.iris.to",
];

/// Relay manager that handles connections and event ingestion (not used with nostr-sdk)
#[allow(dead_code)]
pub struct RelayManager {
    ndb: Ndb,
    shutdown: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl RelayManager {
    pub fn new(ndb: Ndb) -> Self {
        Self {
            ndb,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

/// Configuration for relay subscriptions
#[derive(Clone)]
pub struct RelayConfig {
    pub relays: Vec<String>,
    /// Authors to subscribe to (32-byte pubkeys)
    pub authors: Vec<[u8; 32]>,
    /// Event kinds to subscribe to
    pub kinds: Vec<u64>,
    /// Root pubkey for social graph (used for stats queries)
    pub root_pubkey: Option<[u8; 32]>,
    /// Seed pubkeys to start social graph crawling from
    pub crawl_seeds: Vec<[u8; 32]>,
    /// Maximum crawl depth (0 = disabled, 1 = direct follows, 2 = friends of friends, etc)
    pub crawl_depth: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
            authors: vec![],
            kinds: vec![0, 1, 3, 4, 6, 7, 30023], // profiles, notes, contacts, DMs, reposts, reactions, articles
            root_pubkey: None,
            crawl_seeds: vec![],
            crawl_depth: 0,
        }
    }
}

/// Result from spawning relay thread
pub struct RelayThreadHandle {
    pub shutdown: Arc<AtomicBool>,
    pub query: NdbQuerySender,
}

/// Spawn a background thread that polls relays and ingests events.
/// Uses a dedicated thread since nostrdb::Filter is not Send.
pub fn spawn_relay_thread(ndb: Ndb, config: RelayConfig) -> RelayThreadHandle {
    use crate::crawler::{CrawlerState, contact_list_filter, extract_p_tags, KIND_CONTACTS};
    use std::collections::HashMap;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Channel for queries from other threads
    let (query_tx, query_rx) = mpsc::channel::<NdbQuery>();

    thread::spawn(move || {
        // Create tokio runtime for this thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async move {
            // Create nostr-sdk client
            let client = Client::default();

            // Add relays
            for url in &config.relays {
                if let Err(e) = client.add_relay(url).await {
                    error!("Failed to add relay {}: {}", url, e);
                }
            }

            // Connect to relays
            client.connect().await;

            info!(
                "Relay thread started with {} relays",
                config.relays.len()
            );

            // Build subscription filter
            let mut filter = nostr_sdk::Filter::new();

            if !config.kinds.is_empty() {
                let kinds: Vec<Kind> = config.kinds.iter().map(|k| Kind::from(*k as u16)).collect();
                filter = filter.kinds(kinds);
            }

            if !config.authors.is_empty() {
                let authors: Vec<PublicKey> = config.authors.iter()
                    .filter_map(|pk| PublicKey::from_slice(pk).ok())
                    .collect();
                filter = filter.authors(authors);
            }

            filter = filter.limit(500);

            // Subscribe
            if let Err(e) = client.subscribe(vec![filter], None).await {
                error!("Failed to subscribe: {}", e);
            }

            // Initialize crawler if configured
            let mut crawler = if config.crawl_depth > 0 && !config.crawl_seeds.is_empty() {
                let mut state = CrawlerState::new(config.crawl_depth);
                state.add_seeds(&config.crawl_seeds);
                info!(
                    "Starting social graph crawl with {} seeds, max depth {}",
                    config.crawl_seeds.len(),
                    config.crawl_depth
                );
                Some(state)
            } else {
                None
            };

            // Track active crawl subscriptions: sub_id -> depth
            let mut crawl_subs: HashMap<String, u32> = HashMap::new();
            let mut last_crawl_batch = std::time::Instant::now();
            let crawl_batch_interval = Duration::from_millis(500);
            let mut last_stats_log = std::time::Instant::now();

            // Get notification receiver
            let mut notifications = client.notifications();

            // Main event loop
            while !shutdown_clone.load(Ordering::SeqCst) {
                // Handle notifications with timeout
                let recv_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    notifications.recv()
                ).await;

                if let Ok(Ok(notification)) = recv_result {
                    if let RelayPoolNotification::Event { event, relay_url, .. } = notification {
                        // Ingest event into nostrdb
                        let event_json = event.as_json();
                        let relay_str = relay_url.to_string();
                        if let Err(e) = ndb.process_event_with(
                            &event_json,
                            nostrdb::IngestMetadata::new()
                                .client(false)
                                .relay(&relay_str),
                        ) {
                            debug!("Error processing event: {}", e);
                        } else {
                            trace!("Ingested event from {}", relay_url);
                        }
                    }
                }

                // All database operations use a single transaction per iteration
                if let Ok(txn) = Transaction::new(&ndb) {
                    // Process queries from other threads
                    while let Ok(query) = query_rx.try_recv() {
                        process_query_with_txn(&ndb, &txn, config.root_pubkey.as_ref(), query);
                    }

                    // Handle crawler batching
                    if let Some(ref mut crawler_state) = crawler {
                        let now = std::time::Instant::now();

                        // Send next crawl batch if ready
                        if now.duration_since(last_crawl_batch) >= crawl_batch_interval {
                            if let Some((sub_id, batch, depth)) = crawler_state.next_batch() {
                                let filter = contact_list_filter(&batch);

                                // Convert nostrdb filter to nostr-sdk filter for subscription
                                let sdk_filter = nostr_sdk::Filter::new()
                                    .kind(Kind::ContactList)
                                    .authors(batch.iter().filter_map(|pk| PublicKey::from_slice(pk).ok()));

                                if let Err(e) = client.subscribe(vec![sdk_filter], None).await {
                                    warn!("Failed to subscribe for crawl batch: {}", e);
                                } else {
                                    crawl_subs.insert(sub_id, depth);
                                    last_crawl_batch = now;
                                }

                                // Keep the nostrdb filter reference to avoid unused warning
                                let _ = filter;
                            }
                        }

                        // Process contact lists from ndb to extract follows
                        let contact_filter = FilterBuilder::new()
                            .kinds(vec![KIND_CONTACTS])
                            .limit(100)
                            .build();

                        if let Ok(results) = ndb.query(&txn, &[contact_filter], 100) {
                            for result in results.iter() {
                                let author = result.note.pubkey();
                                if let Some(depth) = crawler_state.get_depth(author) {
                                    let p_tags = extract_p_tags(&ndb, &txn, result.note_key);
                                    if !p_tags.is_empty() {
                                        crawler_state.process_contact_list(author, p_tags, depth);
                                    }
                                }
                            }
                        }

                        // Log progress periodically
                        if now.duration_since(last_stats_log) >= Duration::from_secs(30) {
                            let stats = crawler_state.stats();
                            if stats.seen_count > 0 {
                                info!(
                                    "Social graph crawler: {} users discovered, {} queued",
                                    stats.seen_count,
                                    stats.queue_count
                                );
                            }
                            last_stats_log = now;
                        }
                    }
                }
            }

            info!("Relay thread shutting down");
            let _ = client.disconnect().await;
        });
    });

    RelayThreadHandle {
        shutdown,
        query: NdbQuerySender { tx: query_tx },
    }
}

fn process_query_with_txn(ndb: &Ndb, txn: &Transaction, root_pubkey: Option<&[u8; 32]>, query: NdbQuery) {
    match query {
        NdbQuery::SocialGraphStats { pubkey, reply } => {
            let stats = query_socialgraph_stats_with_txn(ndb, txn, &pubkey);
            let _ = reply.send(stats);
        }
        NdbQuery::SocialGraphRootStats { reply } => {
            let stats = if let Some(root) = root_pubkey {
                query_socialgraph_stats_with_txn(ndb, txn, root)
            } else {
                SocialGraphStats::default()
            };
            let _ = reply.send(stats);
        }
    }
}

fn query_socialgraph_stats_with_txn(ndb: &Ndb, txn: &Transaction, pubkey: &[u8; 32]) -> SocialGraphStats {
    let following = nostrdb::socialgraph::get_followed(txn, ndb, pubkey, 10000);
    let followers = nostrdb::socialgraph::get_followers(txn, ndb, pubkey, 10000);
    let distance = nostrdb::socialgraph::get_follow_distance(txn, ndb, pubkey);
    SocialGraphStats {
        following_count: following.len(),
        followers_count: followers.len(),
        follow_distance: distance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostrdb::Config;
    use tempfile::TempDir;

    fn init_test_ndb(path: std::path::PathBuf) -> Ndb {
        std::fs::create_dir_all(&path).unwrap();
        let config = Config::new().set_ingester_threads(1);
        Ndb::new(path.to_str().unwrap(), &config).unwrap()
    }

    #[test]
    fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.relays.len(), 4);
        assert!(config.relays.contains(&"wss://relay.damus.io".to_string()));
        assert!(config.authors.is_empty());
        assert!(!config.kinds.is_empty());
    }

    #[test]
    fn test_spawn_relay_thread_and_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        // Use a non-existent relay to avoid actual network calls
        let config = RelayConfig {
            relays: vec!["wss://localhost:19999".to_string()],
            authors: vec![],
            kinds: vec![1],
            root_pubkey: None,
            crawl_seeds: vec![],
            crawl_depth: 0,
        };

        let handle = spawn_relay_thread(ndb, config);

        // Thread should be running
        assert!(!handle.shutdown.load(std::sync::atomic::Ordering::SeqCst));

        // Signal shutdown
        handle.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);

        // Give thread time to exit
        std::thread::sleep(Duration::from_millis(200));
    }
}
