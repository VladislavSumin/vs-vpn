# vs-vpn — Custom VPN with SOCKS5 Proxy

## Build & check
- Rust edition 2024 — requires Rust 1.85+
- `cargo build`, `cargo clippy`, `cargo fmt` are the standard quality tools
- No tests exist; `cargo test` passes vacuously

## Architecture
- CLI entrypoint: `src/main.rs` — `clap` with two subcommands
- `cargo run -- server --listen 0.0.0.0:9090` — egress proxy (must run first)
- `cargo run -- client --server <server_addr> --listen 127.0.0.1:1080` — local SOCKS5 proxy
- `src/protocol.rs` — shared SOCKS5 and custom tunnel constants/types
- Custom tunnel protocol: client sends `[atyp][addr][port:2]`, server replies `0x00` on success

## Conventions
- Error handling uses `Box<dyn std::error::Error>` everywhere
- Uses `#[repr(u8)]` enums with `from_u8` constructors for wire protocol
- Logging uses `tracing` with `tracing-subscriber` (fmt + env-filter)
- Default log level is `trace`; override with `RUST_LOG=info` (or `debug`, `warn`, `error`)
