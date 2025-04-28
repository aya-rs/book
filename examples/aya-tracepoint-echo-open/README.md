
# aya-tracepoint-echo-open

This is an experimentation with eBPF tracepoint, using smaller stack space and then, using eBPF Maps.
The intention is to understand how to use the _tracepoints_ made available by the kernel.
The original code is generated using Rust-Aya 0.1.0 and then modified to help   in experimentation.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Run

```bash
RUST_LOG=info cargo xtask run
```
