# tracepoint

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains:
   `rustup toolchain install nightly --component rust-src`
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```
