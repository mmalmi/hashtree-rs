//! Simulation configuration

use rand::Rng;
use rand_distr::{Distribution, Normal, Uniform, Exp};

/// Network simulation configuration
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Number of nodes in the network
    pub node_count: usize,

    /// Number of peers each node connects to
    pub peers_per_node: usize,

    /// Network latency distribution
    pub latency: LatencyDistribution,

    /// Fraction of nodes that are malicious (0.0 - 1.0)
    pub malicious_fraction: f64,

    /// Fraction of nodes that are selfish (0.0 - 1.0)
    pub selfish_fraction: f64,

    /// Fraction of nodes that are freeloaders (0.0 - 1.0)
    pub freeloader_fraction: f64,

    /// Max hops (TTL) for requests
    pub max_ttl: u32,

    /// Churn rate - probability of node leaving per tick
    pub churn_rate: f64,

    /// LRU cache size for tracking requests
    pub request_cache_size: usize,

    /// How many unique content items exist
    pub content_count: usize,

    /// Content size in bytes
    pub content_size: usize,

    /// Seed for random number generator (for reproducibility)
    pub seed: Option<u64>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            node_count: 100,
            peers_per_node: 5,
            latency: LatencyDistribution::Normal { mean_ms: 50.0, std_ms: 20.0 },
            malicious_fraction: 0.0,
            selfish_fraction: 0.0,
            freeloader_fraction: 0.0,
            max_ttl: 6,
            churn_rate: 0.0,
            request_cache_size: 200,
            content_count: 1000,
            content_size: 1024,
            seed: None,
        }
    }
}

impl SimConfig {
    pub fn small() -> Self {
        Self {
            node_count: 20,
            peers_per_node: 3,
            content_count: 100,
            ..Default::default()
        }
    }

    pub fn medium() -> Self {
        Self::default()
    }

    pub fn large() -> Self {
        Self {
            node_count: 1000,
            peers_per_node: 10,
            content_count: 10000,
            ..Default::default()
        }
    }

    pub fn adversarial() -> Self {
        Self {
            malicious_fraction: 0.1,
            selfish_fraction: 0.2,
            freeloader_fraction: 0.1,
            ..Default::default()
        }
    }

    pub fn high_churn() -> Self {
        Self {
            churn_rate: 0.01, // 1% of nodes leave per tick
            ..Default::default()
        }
    }
}

/// Latency distribution for network simulation
#[derive(Debug, Clone)]
pub enum LatencyDistribution {
    /// Fixed latency
    Fixed { ms: u64 },

    /// Normal (Gaussian) distribution
    Normal { mean_ms: f64, std_ms: f64 },

    /// Uniform distribution
    Uniform { min_ms: u64, max_ms: u64 },

    /// Exponential distribution (models network congestion)
    Exponential { mean_ms: f64 },
}

impl LatencyDistribution {
    /// Sample a latency value in milliseconds
    pub fn sample(&self, rng: &mut impl Rng) -> u64 {
        match self {
            Self::Fixed { ms } => *ms,
            Self::Normal { mean_ms, std_ms } => {
                let dist = Normal::new(*mean_ms, *std_ms).unwrap();
                dist.sample(rng).max(1.0) as u64
            }
            Self::Uniform { min_ms, max_ms } => {
                let dist = Uniform::new(*min_ms, *max_ms);
                dist.sample(rng)
            }
            Self::Exponential { mean_ms } => {
                let dist = Exp::new(1.0 / *mean_ms).unwrap();
                dist.sample(rng).max(1.0) as u64
            }
        }
    }
}
