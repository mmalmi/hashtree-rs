//! Social graph crawler - recursively fetches follow lists
//!
//! Crawls the social graph by:
//! 1. Starting with seed pubkeys
//! 2. Subscribing to their contact lists (kind 3)
//! 3. Extracting followed pubkeys from p-tags
//! 4. Recursively crawling up to a configurable depth

use nostrdb::{Filter, FilterBuilder, Ndb, Transaction};
use std::collections::{HashSet, VecDeque};
use tracing::{debug, trace};

/// Contact list event kind (NIP-02)
pub const KIND_CONTACTS: u64 = 3;

/// Crawler state for tracking progress
pub struct CrawlerState {
    /// Pubkeys we've already requested contact lists for
    pub seen: HashSet<[u8; 32]>,
    /// Depth at which each pubkey was discovered
    pub depth_map: std::collections::HashMap<[u8; 32], u32>,
    /// Pubkeys queued for crawling at each depth level
    pub queue: VecDeque<([u8; 32], u32)>, // (pubkey, depth)
    /// Maximum crawl depth (1 = direct follows only)
    pub max_depth: u32,
    /// Batch size for subscription requests
    pub batch_size: usize,
    /// Current subscription ID counter
    pub sub_counter: u32,
}

impl CrawlerState {
    pub fn new(max_depth: u32) -> Self {
        Self {
            seen: HashSet::new(),
            depth_map: std::collections::HashMap::new(),
            queue: VecDeque::new(),
            max_depth,
            batch_size: 500,
            sub_counter: 0,
        }
    }

    /// Get the depth at which a pubkey was discovered
    pub fn get_depth(&self, pubkey: &[u8; 32]) -> Option<u32> {
        self.depth_map.get(pubkey).copied()
    }

    /// Add seed pubkeys to start crawling from
    pub fn add_seeds(&mut self, pubkeys: &[[u8; 32]]) {
        for pk in pubkeys {
            if self.seen.insert(*pk) {
                self.depth_map.insert(*pk, 0);
                self.queue.push_back((*pk, 0));
            }
        }
    }

    /// Get next batch of pubkeys to request contact lists for
    /// Returns (subscription_id, pubkeys, depth) or None if queue is empty
    pub fn next_batch(&mut self) -> Option<(String, Vec<[u8; 32]>, u32)> {
        if self.queue.is_empty() {
            return None;
        }

        let mut batch = Vec::with_capacity(self.batch_size);
        let mut batch_depth = 0;

        while batch.len() < self.batch_size {
            if let Some((pk, depth)) = self.queue.pop_front() {
                batch.push(pk);
                batch_depth = depth;
            } else {
                break;
            }
        }

        if batch.is_empty() {
            return None;
        }

        self.sub_counter += 1;
        let sub_id = format!("crawl_{}", self.sub_counter);

        debug!(
            "Crawler batch {} with {} pubkeys at depth {}",
            sub_id,
            batch.len(),
            batch_depth
        );

        Some((sub_id, batch, batch_depth))
    }

    /// Process a contact list event, extracting followed pubkeys
    /// Returns pubkeys to add to crawl queue
    pub fn process_contact_list(&mut self, author: &[u8; 32], p_tags: Vec<[u8; 32]>, current_depth: u32) {
        if current_depth >= self.max_depth {
            return;
        }

        let next_depth = current_depth + 1;
        let mut added = 0;

        for followed_pk in p_tags {
            if self.seen.insert(followed_pk) {
                self.depth_map.insert(followed_pk, next_depth);
                self.queue.push_back((followed_pk, next_depth));
                added += 1;
            }
        }

        if added > 0 {
            trace!(
                "Added {} new pubkeys from {:?} at depth {}",
                added,
                hex::encode(author),
                next_depth
            );
        }
    }

    /// Check if crawling is complete
    pub fn is_complete(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get progress stats
    pub fn stats(&self) -> CrawlerStats {
        CrawlerStats {
            seen_count: self.seen.len(),
            queue_count: self.queue.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrawlerStats {
    pub seen_count: usize,
    pub queue_count: usize,
}

/// Build a filter for contact lists from specific authors
pub fn contact_list_filter(authors: &[[u8; 32]]) -> Filter {
    FilterBuilder::new()
        .kinds(vec![KIND_CONTACTS])
        .authors(authors.iter())
        .build()
}

/// Extract p-tags (followed pubkeys) from a contact list note
pub fn extract_p_tags(ndb: &Ndb, txn: &Transaction, note_key: nostrdb::NoteKey) -> Vec<[u8; 32]> {
    let note = match ndb.get_note_by_key(txn, note_key) {
        Ok(n) => n,
        Err(_) => return vec![],
    };

    let mut followed = Vec::new();
    let tags = note.tags();

    for tag in tags.iter() {
        // p-tag format: ["p", <pubkey>, ...optional relay/petname]
        if tag.count() >= 2 {
            if let Some(tag_name) = tag.get(0).and_then(|e| e.str()) {
                if tag_name == "p" {
                    if let Some(pk_str) = tag.get(1).and_then(|e| e.str()) {
                        if let Ok(pk_bytes) = hex::decode(pk_str) {
                            if pk_bytes.len() == 32 {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&pk_bytes);
                                followed.push(pk);
                            }
                        }
                    }
                }
            }
        }
    }

    followed
}

/// Check if we have a contact list for a pubkey in the database
pub fn has_contact_list(ndb: &Ndb, txn: &Transaction, pubkey: &[u8; 32]) -> bool {
    let filter = FilterBuilder::new()
        .kinds(vec![KIND_CONTACTS])
        .authors([*pubkey].iter())
        .limit(1)
        .build();

    match ndb.query(txn, &[filter], 1) {
        Ok(results) => !results.is_empty(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_state_basic() {
        let mut state = CrawlerState::new(2);

        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];

        state.add_seeds(&[pk1, pk2]);

        assert_eq!(state.seen.len(), 2);
        assert_eq!(state.queue.len(), 2);

        let batch = state.next_batch().unwrap();
        assert_eq!(batch.1.len(), 2);
        assert_eq!(batch.2, 0); // depth 0

        assert!(state.next_batch().is_none());
    }

    #[test]
    fn test_crawler_state_depth_limit() {
        let mut state = CrawlerState::new(1);

        let seed = [1u8; 32];
        state.add_seeds(&[seed]);

        // Get batch with seed at depth 0
        let batch0 = state.next_batch().unwrap();
        assert_eq!(batch0.1.len(), 1);
        assert_eq!(batch0.2, 0); // depth 0

        // Process contact list at depth 0
        let followed = vec![[2u8; 32], [3u8; 32]];
        state.process_contact_list(&seed, followed, 0);

        // Should add follows at depth 1
        assert_eq!(state.queue.len(), 2);

        // Get batch at depth 1
        let batch = state.next_batch().unwrap();
        assert_eq!(batch.2, 1);

        // Process contact list at depth 1 - should NOT add more (max_depth=1)
        let more_follows = vec![[4u8; 32]];
        state.process_contact_list(&[2u8; 32], more_follows, 1);

        assert!(state.queue.is_empty());
    }

    #[test]
    fn test_crawler_deduplication() {
        let mut state = CrawlerState::new(3);

        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];

        state.add_seeds(&[pk1]);
        state.add_seeds(&[pk1, pk2]); // pk1 is duplicate

        assert_eq!(state.seen.len(), 2);
        assert_eq!(state.queue.len(), 2);
    }

    #[test]
    fn test_crawler_full_crawl_simulation() {
        // Simulate crawling a social graph with depth 2
        let mut state = CrawlerState::new(2);

        // Seed: jb55's pubkey
        let jb55 = {
            let bytes = hex::decode("4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0").unwrap();
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            pk
        };

        state.add_seeds(&[jb55]);
        assert_eq!(state.seen.len(), 1);

        // Get first batch (seed at depth 0)
        let (sub_id, batch, depth) = state.next_batch().unwrap();
        assert!(sub_id.starts_with("crawl_"));
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0], jb55);
        assert_eq!(depth, 0);

        // Simulate receiving jb55's contact list with 3 follows
        let follow1 = [1u8; 32];
        let follow2 = [2u8; 32];
        let follow3 = [3u8; 32];
        state.process_contact_list(&jb55, vec![follow1, follow2, follow3], 0);

        // Should have 3 new pubkeys queued at depth 1
        assert_eq!(state.seen.len(), 4); // jb55 + 3 follows
        assert_eq!(state.queue.len(), 3);

        // Get depth 1 batch
        let (_, batch1, depth1) = state.next_batch().unwrap();
        assert_eq!(batch1.len(), 3);
        assert_eq!(depth1, 1);

        // Simulate receiving follow1's contact list
        let follow1_follows = vec![[10u8; 32], [11u8; 32]];
        state.process_contact_list(&follow1, follow1_follows, 1);

        // Should have 2 new pubkeys at depth 2
        assert_eq!(state.seen.len(), 6);
        assert_eq!(state.queue.len(), 2);

        // Get depth 2 batch
        let (_, batch2, depth2) = state.next_batch().unwrap();
        assert_eq!(batch2.len(), 2);
        assert_eq!(depth2, 2);

        // Processing at depth 2 should NOT add more (max_depth=2)
        state.process_contact_list(&[10u8; 32], vec![[100u8; 32]], 2);
        assert_eq!(state.seen.len(), 6); // No change
        assert!(state.queue.is_empty());
        assert!(state.is_complete());
    }

    #[test]
    fn test_crawler_stats() {
        let mut state = CrawlerState::new(2);
        state.add_seeds(&[[1u8; 32], [2u8; 32]]);

        let stats = state.stats();
        assert_eq!(stats.seen_count, 2);
        assert_eq!(stats.queue_count, 2);

        state.next_batch();
        let stats2 = state.stats();
        assert_eq!(stats2.seen_count, 2);
        assert_eq!(stats2.queue_count, 0);
    }

    #[test]
    fn test_contact_list_filter() {
        let authors = vec![[1u8; 32], [2u8; 32]];
        let filter = contact_list_filter(&authors);
        // Filter should be built without panic
        assert!(filter.as_ptr() != std::ptr::null());
    }
}
