//! Node behavior strategies
//!
//! Determines how nodes respond to requests:
//! - Forward or drop?
//! - Cache or discard?
//! - Respond honestly or lie?
//! - Send garbage sometimes?

use crate::message::Hash;
use crate::NodeId;
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

    /// Should this node forward requests to other peers?
    pub fn should_forward(&self) -> bool {
        match self {
            Behavior::Cooperative(_) => true,
            Behavior::Selfish => false,
            Behavior::Freeloader => false,
            Behavior::Malicious(_) => true,
            Behavior::Probabilistic(_) => true,
        }
    }

    /// Should this node cache data it receives?
    pub fn should_cache(&self, _hash: &Hash, _data: &[u8]) -> bool {
        match self {
            Behavior::Cooperative(_) => true,
            Behavior::Selfish => true, // still caches for own benefit
            Behavior::Freeloader => false,
            Behavior::Malicious(_) => true,
            Behavior::Probabilistic(p) => rand::thread_rng().gen_bool(p.cache_probability),
        }
    }

    /// Select which peers to forward request to
    pub fn select_peers<R: Rng>(
        &self,
        available: &[NodeId],
        exclude: NodeId,
        rng: &mut R,
    ) -> Vec<NodeId> {
        match self {
            Behavior::Cooperative(coop) => {
                let mut peers: Vec<_> = available
                    .iter()
                    .filter(|&&id| id != exclude)
                    .copied()
                    .collect();

                if coop.max_forward > 0 && peers.len() > coop.max_forward {
                    // Random subset
                    for i in (1..peers.len()).rev() {
                        let j = rng.gen_range(0..=i);
                        peers.swap(i, j);
                    }
                    peers.truncate(coop.max_forward);
                }
                peers
            }
            Behavior::Selfish | Behavior::Freeloader => vec![],
            Behavior::Malicious(_) => available
                .iter()
                .filter(|&&id| id != exclude)
                .copied()
                .collect(),
            Behavior::Probabilistic(prob) => available
                .iter()
                .filter(|&&id| id != exclude)
                .filter(|_| rng.gen_bool(prob.forward_probability))
                .copied()
                .collect(),
        }
    }

    /// Should this node respond with wrong data?
    pub fn should_lie<R: Rng>(&self, rng: &mut R) -> bool {
        match self {
            Behavior::Malicious(m) => rng.gen_bool(m.lie_probability),
            _ => false,
        }
    }

    /// Should this node send garbage bytes instead of valid message?
    pub fn should_send_garbage<R: Rng>(&self, rng: &mut R) -> bool {
        match self {
            Behavior::Malicious(m) => rng.gen_bool(m.garbage_probability),
            _ => false,
        }
    }

    /// Generate garbage bytes of given length
    pub fn generate_garbage<R: Rng>(&self, len: usize, rng: &mut R) -> Vec<u8> {
        let mut garbage = vec![0u8; len];
        rng.fill_bytes(&mut garbage);
        garbage
    }
}

/// Normal cooperative node - forwards, caches, honest
#[derive(Debug, Clone, Default)]
pub struct Cooperative {
    /// Max peers to forward to (0 = all)
    pub max_forward: usize,
}

/// Malicious node - sometimes lies or sends garbage
#[derive(Debug, Clone)]
pub struct Malicious {
    /// Probability of sending wrong data (0.0 - 1.0)
    pub lie_probability: f64,
    /// Probability of sending garbage bytes (0.0 - 1.0)
    pub garbage_probability: f64,
}

impl Default for Malicious {
    fn default() -> Self {
        Self {
            lie_probability: 0.3,
            garbage_probability: 0.1,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cooperative_forwards() {
        let b = Behavior::cooperative();
        assert!(b.should_forward());
    }

    #[test]
    fn test_selfish_no_forward() {
        let b = Behavior::selfish();
        assert!(!b.should_forward());
    }

    #[test]
    fn test_malicious_can_lie() {
        let b = Behavior::Malicious(Malicious {
            lie_probability: 1.0,
            garbage_probability: 0.0,
        });
        let mut rng = rand::thread_rng();
        assert!(b.should_lie(&mut rng));
    }

    #[test]
    fn test_malicious_can_send_garbage() {
        let b = Behavior::Malicious(Malicious {
            lie_probability: 0.0,
            garbage_probability: 1.0,
        });
        let mut rng = rand::thread_rng();
        assert!(b.should_send_garbage(&mut rng));

        let garbage = b.generate_garbage(100, &mut rng);
        assert_eq!(garbage.len(), 100);
    }
}
