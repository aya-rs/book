# tc-byte-count

This application is intended to demonstrate how to use several imporant BPF primitives via aya, including:

1. Basic eBPF program attachment for Traffic Control (TC).
1. How to instrument ingress and egress traffic.
1. Lock free telemetry aggregation between kernel (eBPF) and userpsace programs.

The example program itself uses a realistic scenario where the author wishes to emitt metrics about ingress and 
egress network traffic data rates grouped by remote port. The data is gathered using eBPF programs attached to 
the tc_egress and tc_ingress instrumentation points in the kernel. Each packet is inspected and then the byte 
count of the packet is incremented for the packets remote port in a "per-cpu" map. These "pre-cpu" maps allow 
us to avoid using locks for our get-increment-put operation on the map. The userspace program them periodically 
aggregates the map data, summing the per-cpu values in order to produce a set of percentiles that are logged 
every second. This is precisely the kind of data one might want when sizing or monitoring a bursty network 
application that is also sensitive to data loss.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
