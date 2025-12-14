//! Outbound relay connections - connecting to other relays
//!
//! Handles connecting to nostr relays and ingesting events into nostrdb.

use anyhow::Result;
use enostr::{RelayEvent, RelayPool};
use nostrdb::{Filter, FilterBuilder, Ndb, Transaction};
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
    /// Check if a pubkey is muted by root
    IsMutedByRoot {
        pubkey: [u8; 32],
        reply: mpsc::Sender<bool>,
    },
}

/// Social graph statistics
#[derive(Debug, Clone, Default)]
pub struct SocialGraphStats {
    pub following_count: usize,
    pub followers_count: usize,
    pub follow_distance: u32,
    /// Number of users in the social graph who mute this user
    pub muter_count: usize,
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

    /// Check if a pubkey is muted by the root user
    pub fn is_muted_by_root(&self, pubkey: [u8; 32]) -> Result<bool> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx.send(NdbQuery::IsMutedByRoot { pubkey, reply: reply_tx })?;
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

/// Result of processing relay events
#[derive(Default)]
pub struct ProcessResult {
    /// Number of events processed
    pub event_count: usize,
    /// Subscription IDs that received EOSE
    pub eose_subs: Vec<String>,
}

/// Relay manager that handles connections and event ingestion
pub struct RelayManager {
    pool: RelayPool,
    ndb: Ndb,
    shutdown: Arc<AtomicBool>,
}

impl RelayManager {
    pub fn new(ndb: Ndb) -> Self {
        Self {
            pool: RelayPool::new(),
            ndb,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add a relay URL to the pool
    pub fn add_relay(
        &mut self,
        url: &str,
        wakeup: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Result<()> {
        self.pool.add_url(url.to_string(), wakeup)?;
        Ok(())
    }

    /// Add default relays
    pub fn add_default_relays(
        &mut self,
        wakeup: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Result<()> {
        for url in DEFAULT_RELAYS {
            if let Err(e) = self.add_relay(url, wakeup.clone()) {
                warn!("Failed to add relay {}: {}", url, e);
            }
        }
        Ok(())
    }

    /// Subscribe to events matching the filter
    pub fn subscribe(&mut self, subid: String, filters: Vec<Filter>) {
        self.pool.subscribe(subid, filters);
    }

    /// Process pending relay events, ingesting into nostrdb
    /// Returns processing results including event count and completed subscriptions
    pub fn process_events(&mut self) -> ProcessResult {
        let mut result = ProcessResult {
            event_count: 0,
            eose_subs: Vec::new(),
        };

        loop {
            let pool_event = if let Some(ev) = self.pool.try_recv() {
                ev.into_owned()
            } else {
                break;
            };

            match (&pool_event.event).into() {
                RelayEvent::Opened => {
                    info!("Relay connected: {}", pool_event.relay);
                }
                RelayEvent::Closed => {
                    warn!("Relay disconnected: {}", pool_event.relay);
                }
                RelayEvent::Error(e) => {
                    error!("Relay {} error: {}", pool_event.relay, e);
                }
                RelayEvent::Other(_) => {}
                RelayEvent::Message(msg) => {
                    use enostr::RelayMessage;
                    match msg {
                        RelayMessage::Event(subid, ev) => {
                            info!("EVENT received from {} sub={}", pool_event.relay, subid);
                            if let Err(e) = self.ndb.process_event_with(
                                &ev,
                                nostrdb::IngestMetadata::new()
                                    .client(false)
                                    .relay(&pool_event.relay),
                            ) {
                                debug!("Error processing event: {}", e);
                            } else {
                                result.event_count += 1;
                            }
                        }
                        RelayMessage::Notice(msg) => {
                            warn!("Notice from {}: {}", pool_event.relay, msg);
                        }
                        RelayMessage::OK(cr) => {
                            debug!("OK from {}: {:?}", pool_event.relay, cr);
                        }
                        RelayMessage::Eose(subid) => {
                            debug!("EOSE from {} for {}", pool_event.relay, subid);
                            result.eose_subs.push(subid.to_string());
                        }
                    }
                }
            }
        }

        result
    }

    /// Keep connections alive
    pub fn keepalive(&mut self, wakeup: impl Fn() + Send + Sync + Clone + 'static) {
        self.pool.keepalive_ping(wakeup);
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get relay URLs
    pub fn relay_urls(&self) -> Vec<String> {
        self.pool.urls().into_iter().collect()
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
    use crate::crawler::{CrawlerState, contact_list_filter, contact_and_mute_filter, extract_p_tags, KIND_CONTACTS, KIND_MUTE_LIST};
    use std::collections::HashMap;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Channel for queries from other threads
    let (query_tx, query_rx) = mpsc::channel::<NdbQuery>();

    thread::spawn(move || {
        // Channel for wakeups from websocket events
        let (wakeup_tx, wakeup_rx) = std::sync::mpsc::channel::<()>();

        let wakeup = move || {
            let _ = wakeup_tx.send(());
        };

        let mut manager = RelayManager::new(ndb);

        // Add relays
        for url in &config.relays {
            if let Err(e) = manager.add_relay(url, wakeup.clone()) {
                error!("Failed to add relay {}: {}", url, e);
            }
        }

        // Build subscription filter for main events
        let mut filter_builder = FilterBuilder::new();

        if !config.kinds.is_empty() {
            filter_builder = filter_builder.kinds(config.kinds.clone());
        }

        if !config.authors.is_empty() {
            filter_builder = filter_builder.authors(config.authors.iter());
        }

        filter_builder = filter_builder.limit(500);

        let filter = filter_builder.build();
        manager.subscribe("hashtree".to_string(), vec![filter]);

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

        // Live subscription state - subscribed to follows/mutes of social graph users
        let mut live_sub_active = false;
        // Track when crawl appears complete to add delay for ndb indexing
        let mut crawl_complete_time: Option<std::time::Instant> = None;

        info!(
            "Relay thread started with {} relays",
            config.relays.len()
        );

        let keepalive_interval = Duration::from_secs(30);
        let mut last_keepalive = std::time::Instant::now();

        while !shutdown_clone.load(Ordering::SeqCst) {
            // Wait for wakeup or timeout
            match wakeup_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(_) => trace!("Wakeup received"),
                Err(_) => {} // timeout, normal
            }

            // Process relay events
            let result = manager.process_events();
            if result.event_count > 0 {
                info!("Processed {} events from relays", result.event_count);
            }

            // Handle EOSE for crawl subscriptions
            for subid in result.eose_subs {
                if subid.starts_with("crawl_") {
                    if crawl_subs.remove(&subid).is_some() {
                        debug!("Crawl subscription {} completed (EOSE)", subid);
                    }
                }
            }

            // All database operations use a single transaction per iteration
            // nostrdb only allows one transaction per thread at a time
            if let Ok(txn) = Transaction::new(&manager.ndb) {
                // Process queries from other threads
                while let Ok(query) = query_rx.try_recv() {
                    process_query_with_txn(&manager.ndb, &txn, config.root_pubkey.as_ref(), query);
                }

                // Handle crawler batching
                if let Some(ref mut crawler_state) = crawler {
                    let now = std::time::Instant::now();

                    // Send next crawl batch if ready
                    if now.duration_since(last_crawl_batch) >= crawl_batch_interval {
                        if let Some((sub_id, batch, depth)) = crawler_state.next_batch() {
                            let filter = contact_list_filter(&batch);
                            manager.subscribe(sub_id.clone(), vec![filter]);
                            crawl_subs.insert(sub_id, depth);
                            last_crawl_batch = now;
                        }
                    }

                    // Process contact lists and mute lists from ndb to extract follows
                    // Query specifically for users in our depth_map, in batches to avoid filter limits
                    let known_users: Vec<[u8; 32]> = crawler_state.seen.iter().copied().collect();
                    let query_batch_size = 500; // Limit authors per query to avoid nostrdb filter limits
                    for chunk in known_users.chunks(query_batch_size) {
                        let contact_filter = FilterBuilder::new()
                            .kinds(vec![KIND_CONTACTS, KIND_MUTE_LIST])
                            .authors(chunk.iter())
                            .build();

                        match manager.ndb.query(&txn, &[contact_filter], chunk.len() as i32) {
                            Ok(results) => {
                                for result in results.iter() {
                                    let author = result.note.pubkey();
                                    if let Some(depth) = crawler_state.get_depth(author) {
                                        let p_tags = extract_p_tags(&manager.ndb, &txn, result.note_key);
                                        if !p_tags.is_empty() {
                                            debug!("Contact list from {} has {} follows at depth {}",
                                                hex::encode(author), p_tags.len(), depth);
                                            crawler_state.process_contact_list(author, p_tags, depth);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to query contact lists: {}", e);
                            }
                        }
                    }

                    // Log progress periodically
                    let stats = crawler_state.stats();
                    if stats.queue_count > 0 || !crawl_subs.is_empty() {
                        trace!(
                            "Crawler: {} seen, {} queued, {} active subs",
                            stats.seen_count,
                            stats.queue_count,
                            crawl_subs.len()
                        );
                    }

                    // Start live subscription once crawl is complete (with delay for ndb indexing)
                    let crawl_appears_done = stats.queue_count == 0 && crawl_subs.is_empty();
                    if crawl_appears_done && crawl_complete_time.is_none() {
                        crawl_complete_time = Some(std::time::Instant::now());
                        debug!("Crawl appears complete, waiting for ndb to index...");
                    } else if !crawl_appears_done {
                        crawl_complete_time = None; // Reset if more work appears
                    }

                    // Wait 2 seconds after crawl appears complete to ensure ndb has indexed
                    let ready_for_live = crawl_complete_time
                        .map(|t| t.elapsed() >= Duration::from_secs(2))
                        .unwrap_or(false);

                    if !live_sub_active && ready_for_live && stats.seen_count > 0 {
                        // Subscribe to follows/mutes of all discovered users
                        let users: Vec<[u8; 32]> = crawler_state.seen.iter().copied().collect();
                        if !users.is_empty() {
                            // Split into batches to avoid too large subscriptions
                            let batch_size = 500;
                            for (i, chunk) in users.chunks(batch_size).enumerate() {
                                let filter = contact_and_mute_filter(chunk);
                                let sub_id = format!("live_{}", i);
                                manager.subscribe(sub_id.clone(), vec![filter]);
                                info!("Started live subscription {} for {} users", sub_id, chunk.len());
                            }
                            live_sub_active = true;
                            info!("Live subscription active for {} social graph users (follows & mutes)", users.len());
                        }
                    }
                }
            }

            // Keepalive
            if last_keepalive.elapsed() >= keepalive_interval {
                let wakeup_clone = {
                    let tx = wakeup_rx.try_iter().collect::<Vec<_>>();
                    drop(tx);
                    let (tx, _) = std::sync::mpsc::channel::<()>();
                    move || {
                        let _ = tx.send(());
                    }
                };
                manager.keepalive(wakeup_clone);
                last_keepalive = std::time::Instant::now();

                // Log crawler stats on keepalive
                if let Some(ref crawler_state) = crawler {
                    let stats = crawler_state.stats();
                    if stats.seen_count > 0 {
                        info!(
                            "Social graph crawler: {} users discovered, {} queued",
                            stats.seen_count,
                            stats.queue_count
                        );
                    }
                }
            }
        }

        info!("Relay thread shutting down");
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
        NdbQuery::IsMutedByRoot { pubkey, reply } => {
            let is_muted = if let Some(root) = root_pubkey {
                nostrdb::socialgraph::is_muting(txn, ndb, root, &pubkey)
            } else {
                false
            };
            let _ = reply.send(is_muted);
        }
    }
}

fn query_socialgraph_stats_with_txn(ndb: &Ndb, txn: &Transaction, pubkey: &[u8; 32]) -> SocialGraphStats {
    let following = nostrdb::socialgraph::get_followed(txn, ndb, pubkey, 10000);
    let followers = nostrdb::socialgraph::get_followers(txn, ndb, pubkey, 10000);
    let distance = nostrdb::socialgraph::get_follow_distance(txn, ndb, pubkey);
    let muter_count = nostrdb::socialgraph::muter_count(txn, ndb, pubkey);
    SocialGraphStats {
        following_count: following.len(),
        followers_count: followers.len(),
        follow_distance: distance,
        muter_count,
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
    fn test_relay_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        let manager = RelayManager::new(ndb);
        assert!(manager.relay_urls().is_empty());
    }

    #[test]
    fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.relays.len(), 3);
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

    #[test]
    fn test_relay_manager_add_relay() {
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        let mut manager = RelayManager::new(ndb);

        // Adding relay should work (will try to connect but we don't wait)
        let wakeup = || {};
        let result = manager.add_relay("wss://relay.damus.io", wakeup);
        // The result depends on whether connection succeeds
        let _ = result;
    }

    #[test]
    #[ignore] // Run with: cargo test --ignored test_crawler_live
    fn test_crawler_live_crawl() {
        // This test actually connects to relays and crawls the social graph
        // Run manually with: cargo test -p hashtree-relay test_crawler_live -- --ignored --nocapture
        let temp_dir = TempDir::new().unwrap();
        let ndb = init_test_ndb(temp_dir.path().join("nostrdb"));

        // Sirius's pubkey (npub1g53mukxnjkcmr94fhryzkqutdz2ukq4ks0gvy5af25rgmwsl4ngq43drvk)
        let sirius = {
            let bytes = hex::decode("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0").unwrap();
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            pk
        };

        // Set sirius as social graph root
        nostrdb::socialgraph::set_root(&ndb, &sirius);

        let config = RelayConfig {
            relays: vec![
                "wss://relay.damus.io".to_string(),
                "wss://relay.snort.social".to_string(),
                "wss://temp.iris.to".to_string(),
                "wss://vault.iris.to".to_string(),
            ],
            authors: vec![],
            kinds: vec![],
            root_pubkey: Some(sirius),
            crawl_seeds: vec![sirius],
            crawl_depth: 1, // Just direct follows for speed
        };

        let handle = spawn_relay_thread(ndb.clone(), config);

        // Wait for crawling to happen
        println!("Crawling social graph from sirius (depth 1)...");
        std::thread::sleep(Duration::from_secs(10));

        // Query social graph stats while still running - root stats should work
        let stats = handle.query.socialgraph_root_stats();
        println!("Stats for root (sirius): {:?}", stats);

        // Check we got some data
        if let Ok(s) = stats {
            println!("Following: {}, Followers: {}, Distance: {}", s.following_count, s.followers_count, s.follow_distance);
            // Root user should have distance 0
            assert_eq!(s.follow_distance, 0, "Root user should have follow_distance 0");
            // Sirius should have some follows
            assert!(s.following_count > 0, "Should have discovered following data");
        }

        // Signal shutdown
        handle.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(500));
    }
}
