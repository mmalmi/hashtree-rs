# Agent Guidelines

## Testing Requirements

- **Flaky tests are NOT accepted**. All tests must be deterministic and reliable.
- If a test involves network operations (WebRTC, Nostr relays), it must either:
  1. Use mocks/stubs for deterministic behavior (preferred)
  2. Use the local `WsRelay` from hashtree-sim for Nostr signaling tests
  3. Be marked as `#[ignore]` ONLY if it requires external infrastructure that cannot be mocked (e.g., STUN/TURN servers for WebRTC ICE)

- WebRTC peer connection tests require STUN/ICE which needs network infrastructure. These should be marked as `#[ignore]` and can be run manually with `--ignored`.
- Nostr signaling tests should use `hashtree_sim::WsRelay` for a local in-memory relay.
