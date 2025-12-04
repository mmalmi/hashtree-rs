//! Node behavior strategies

use crate::{NodeId, message::{Hash, Request}};
use rand::Rng;

/// Enum representing different node behaviors
#[derive(Debug, Clone)]
pub enum Behavior {
    Cooperative(Cooperative),
    Selfish,
    Freeloader,
    Malicious(Malicious),
    Probabilistic(Probabilistic),
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior::Cooperative(Cooperative::default())
    }
}

impl Behavior {
    pub fn cooperative() -> Self {
        Behavior::Cooperative(Cooperative::default())
    }

    pub fn selfish() -> Self {
        Behavior::Selfish
    }

    pub fn freeloader() -> Self {
        Behavior::Freeloader
    }

    pub fn malicious() -> Self {
        Behavior::Malicious(Malicious::default())
    }

    pub fn probabilistic(forward_prob: f64, cache_prob: f64) -> Self {
        Behavior::Probabilistic(Probabilistic {
            forward_probability: forward_prob,
            cache_probability: cache_prob,
        })
    }

    /// Should this node forward the request to other peers?
    pub fn should_forward(&self, req: &Request) -> bool {
        match self {
            Behavior::Cooperative(_) => req.can_forward(),
            Behavior::Selfish => false,
            Behavior::Freeloader => false,
            Behavior::Malicious(_) => req.can_forward(),
            Behavior::Probabilistic(_) => req.can_forward(),
        }
    }

    /// Should this node cache data it receives?
    pub fn should_cache(&self, _hash: &Hash, _data: &[u8]) -> bool {
        match self {
            Behavior::Cooperative(_) => true,
            Behavior::Selfish => true, // still caches for own benefit
            Behavior::Freeloader => false,
            Behavior::Malicious(_) => true,
            Behavior::Probabilistic(_) => true,
        }
    }

    /// Select which peers to forward request to
    pub fn select_peers<R: Rng>(
        &self,
        _req: &Request,
        available: &[NodeId],
        exclude: NodeId,
        rng: &mut R,
    ) -> Vec<NodeId> {
        match self {
            Behavior::Cooperative(coop) => {
                let mut peers: Vec<_> = available.iter()
                    .filter(|&&id| id != exclude)
                    .copied()
                    .collect();

                if coop.max_forward > 0 && peers.len() > coop.max_forward {
                    // Random subset using Fisher-Yates shuffle
                    for i in (1..peers.len()).rev() {
                        let j = rng.gen_range(0..=i);
                        peers.swap(i, j);
                    }
                    peers.truncate(coop.max_forward);
                }
                peers
            }
            Behavior::Selfish | Behavior::Freeloader => vec![],
            Behavior::Malicious(_) => {
                available.iter()
                    .filter(|&&id| id != exclude)
                    .copied()
                    .collect()
            }
            Behavior::Probabilistic(prob) => {
                available.iter()
                    .filter(|&&id| id != exclude)
                    .filter(|_| rng.gen_bool(prob.forward_probability))
                    .copied()
                    .collect()
            }
        }
    }

    /// Should this node respond with wrong data? (for malicious nodes)
    pub fn should_lie<R: Rng>(&self, rng: &mut R) -> bool {
        match self {
            Behavior::Malicious(m) => rng.gen_bool(m.lie_probability),
            _ => false,
        }
    }
}

/// Normal cooperative node - forwards, caches, honest
#[derive(Debug, Clone, Default)]
pub struct Cooperative {
    /// Max peers to forward to (0 = all)
    pub max_forward: usize,
}

/// Malicious node - sometimes returns wrong data
#[derive(Debug, Clone)]
pub struct Malicious {
    /// Probability of lying (0.0 - 1.0)
    pub lie_probability: f64,
}

impl Default for Malicious {
    fn default() -> Self {
        Self { lie_probability: 0.5 }
    }
}

/// Probabilistic forwarder - forwards with some probability
#[derive(Debug, Clone)]
pub struct Probabilistic {
    pub forward_probability: f64,
    pub cache_probability: f64,
}

impl Default for Probabilistic {
    fn default() -> Self {
        Self {
            forward_probability: 0.8,
            cache_probability: 0.5,
        }
    }
}
