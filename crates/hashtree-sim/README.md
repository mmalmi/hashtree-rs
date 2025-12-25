# hashtree-sim

P2P network simulation for hashtree, testing routing strategies and network behavior.

## Shared Code with Production

The simulation uses the **same types and defaults as production WebRTC**:

```rust
// Uses hashtree_webrtc::PoolConfig - same defaults as real WebRTC
let config = SimConfig {
    pool: PoolConfig::default(),  // max_connections: 10, satisfied_connections: 5
    ..Default::default()
};
```

This ensures simulation behavior matches production as closely as possible.

## Network Connectivity

### The Component Problem

In P2P networks, nodes may form disconnected "components" (islands) if there aren't enough connections. A fully connected network has exactly 1 component.

**Graph theory**: For N nodes with k connections each, connectivity requires `k > ln(N)`:

| Nodes | ln(N) | Real WebRTC default (10) |
|-------|-------|--------------------------|
| 50    | 3.9   | Well connected           |
| 100   | 4.6   | Well connected           |
| 200   | 5.3   | Well connected           |
| 1000  | 6.9   | Well connected           |
| 10000 | 9.2   | Edge case                |

The default `max_connections: 10` works well for networks up to ~10K nodes.

### Discovery and Tie-Breaking

Nodes discover each other via Hello messages on a mock relay. When two nodes see each other's Hello, they use a **deterministic tie-breaker** to decide who initiates:

```rust
// Lower peer_id initiates connection
let should_initiate = local_peer_id < remote_peer_id;
```

This is the same logic used in production WebRTC (`should_initiate_connection()` in `hashtree-webrtc`).

## Routing Strategies

### Flooding
- Sends requests to ALL connected peers simultaneously
- First response wins
- High bandwidth, low latency
- Good for small networks or when speed is critical

### Adaptive
- Tries peers sequentially, ordered by past performance
- Learns which peers have data and respond quickly
- Low bandwidth, slightly higher latency
- Uses exponential backoff for slow/unreliable peers

## Latency Simulation

Per-link latency is configurable:
- `network_latency_ms`: Mean latency (e.g., 50ms for realistic WebRTC)
- `latency_variation`: How much latency varies per link (0.0-1.0)
- `latency_seed`: Seed for reproducible latency distribution

Each link gets a fixed latency drawn from a distribution centered on `network_latency_ms`.

## Multi-Hop Forwarding (HTL)

Requests include a **Hops-To-Live** counter (like Freenet):
- Starts at MAX_HTL (10)
- Decremented at each hop (with probabilistic variation per-peer)
- When HTL=0, request is not forwarded further
- Prevents infinite loops and limits network load

## Running Simulations

```bash
# Basic simulation
cargo run --example run_simulation

# With options
cargo run --example run_simulation -- \
  --nodes 200 \
  --strategy adaptive \
  --latency 50 \
  --seed 42

# Benchmark mode (measures throughput)
cargo run --example run_simulation -- --bench --nodes 100

# Burst benchmark (realistic load)
cargo run --example run_simulation -- --burst --nodes 50

# Multiple runs for variance analysis
cargo run --example run_simulation -- --bench --runs 5
```

## Key Learnings

1. **max_peers matters**: Too low (< ln(N)) causes network fragmentation
2. **Adaptive beats Flooding** for bandwidth efficiency once it learns peer quality
3. **Latency variation** is important - uniform latency is unrealistic
4. **Multi-hop forwarding** dramatically increases reach but adds latency
5. **Tie-breaking** must be deterministic to prevent duplicate connections
