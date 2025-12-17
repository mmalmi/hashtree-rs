# Agent Guidelines

- **Features require passing e2e tests** before being marked complete
- **No flaky tests** - all tests must be deterministic
- Use `hashtree_sim::WsRelay` for Nostr signaling tests
- Mark tests `#[ignore]` only if they need external infra (STUN/TURN)
