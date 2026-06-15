# vs-vpn — Custom VPN with SOCKS5 Proxy

## Build & check
- Rust edition 2024 — requires Rust 1.85+
- `cargo build`, `cargo test`, `cargo fmt --check`, `cargo clippy -- -D warnings`
- CI enforces the full chain above (build → test → fmt → clippy)

## Architecture
- CLI entrypoint: `src/main.rs` — `clap` with three subcommands
- `cargo run -- server --listen 0.0.0.0:9090` — egress proxy (run first)
- `cargo run -- client --server <server_addr> --listen 127.0.0.1:1080` — local SOCKS5 proxy
- `cargo run -- keygen` — generate a hex-encoded 32-byte PSK
- `src/protocol.rs` — SOCKS5 constants/types + custom tunnel header encode/decode
- Custom tunnel protocol: client sends `[atyp][addr][port:2]`, server replies `0x00` on success (plain) or error code; same data sent as encrypted frame when `--secret` is used
- Encrypted mode (`--secret <hex>`): ChaCha20Poly1305 AEAD cipher with HKDF-SHA256 session-key derivation from PSK + nonce exchange (`src/crypto.rs`)
- `tests/integration.rs` — end-to-end tests that spawn server + client in-process
- Server and client `run` functions accept an optional `oneshot::Sender<SocketAddr>` for test binding discovery

## Conventions
- Все внешние зависимости (crates.io) должны быть объявлены только в корневом `Cargo.toml` в секции `[workspace.dependencies]`. В `Cargo.toml` под-крейтов используются только `{ workspace = true }` и path-зависимости.
- Error handling uses `Box<dyn std::error::Error>` everywhere
- Logging: `tracing` + `tracing-subscriber` (fmt + env-filter); default level `trace`, override with `RUST_LOG=info`
- Span propagation: на многопоточном рантайме tokio `Span::enter()` теряется при миграции задачи между тредами. Всегда используйте `.instrument(span)` на future перед `tokio::spawn` (трейт `tracing::Instrument`). Дочерние спаны создавайте через `info_span!(parent: Span::current(), ...)`, чтобы сохранить иерархию. Никогда не полагайтесь на `let _enter = span.enter()` внутри `tokio::spawn` — он не переживёт переброс на другой поток.
- Duration values in logs must use human-readable format via `Debug` (e.g. `?start.elapsed()`), never a raw millisecond integer
- Comments must be written in Russian
- Never delete or modify user-written comments without a clear reason
