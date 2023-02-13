# kprobetcp
A test eBPF Aya-based Rust program that attached a bpf handler to kprobe on `tcp_connect`
and prints the source and destination IP addreses from the sockets for the TCP connections (IPv4 and IPv6).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
Execute some TCP connection in a different terminal, such as `curl http://example.com`.  The expected output (the source IP address will likely be different):
```
[2022-12-28T20:50:00Z INFO  kprobetcp] Waiting for Ctrl-C...
[2022-12-28T20:50:05Z INFO  kprobetcp] AF_INET6 src addr: 2001:4998:efeb:282::249, dest addr: 2606:2800:220:1:248:1893:25c8:1946
[2022-12-28T20:50:11Z INFO  kprobetcp] AF_INET src address: 10.53.149.148, dest address: 10.87.116.72
```
