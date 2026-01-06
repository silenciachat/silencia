# Contributing to Silencia

Thanks for your interest in contributing to Silencia! This project aims to build post-quantum private chat with zero-knowledge verified personhood.

## Getting Started

### Prerequisites
- Rust 1.75+ (`rustup update`)
- Optional: liboqs for post-quantum crypto (will fall back to classical-only)

### Building
```bash
git clone https://github.com/senseix21/silencia.git
cd silencia
cargo build
cargo test
```

## Development Workflow

1. **Check issues**: Look for `good-first-issue` or `help-wanted` labels
2. **Create a branch**: `git checkout -b feature/your-feature`
3. **Make changes**: Follow coding standards below
4. **Test**: `cargo test --all-features`
5. **Format**: `cargo fmt`
6. **Lint**: `cargo clippy -- -D warnings`
7. **Commit**: Use conventional commits (e.g., `feat:`, `fix:`, `docs:`)
8. **Push & PR**: Open a pull request with clear description

## Coding Standards

- **Format**: Use `rustfmt` (run `cargo fmt`)
- **Lint**: Zero clippy warnings (`cargo clippy`)
- **Tests**: Add tests for new functionality
- **Docs**: Document public APIs with `///` comments
- **Security**: Zeroize sensitive data; use constant-time comparisons
- **Privacy**: No telemetry without explicit opt-in

## Architecture Guidelines

- **Crates**: Keep crates focused and minimal
- **Dependencies**: Justify new dependencies; prefer battle-tested crates
- **Error handling**: Use `thiserror` for libraries, `anyhow` for apps
- **Async**: Use `tokio` runtime; avoid blocking in async contexts
- **Crypto**: Never roll your own; use audited implementations

## Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test '*'

# With post-quantum features
cargo test --all-features

# Specific crate
cargo test -p silencia-crypto
```

## Security

Report vulnerabilities to: security@silencia.org (PGP key in SECURITY.md)

Do NOT open public issues for security bugs.

## License

By contributing, you agree that your contributions will be:
- Core crates (`silencia-*`): AGPL-3.0
- SDK & examples: Apache-2.0

---

Questions? Open a discussion or join our chat (once alpha is live!)
