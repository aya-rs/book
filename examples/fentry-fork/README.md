# fentry-fork

A test eBPF Aya-based Rust program that attaches fentry and fexit handlers
to `kernel_clone` and prints the PID of the process that creates a new
process and the PID of the newly created process (excluding thread
creation).

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
RUST_LOG=info cargo run
```

Run any command that creates a new process in a different terminal, such as
`ls` or `bash -c true`. The expected output (the PIDs will likely be
different):

<!-- markdownlint-disable MD013 -->

```console
[2022-12-28T20:50:00Z INFO  fentry_fork] Waiting for Ctrl-C...
[2022-12-28T20:50:05Z INFO  fentry_fork] Process creation is started by: 12345
[2022-12-28T20:50:05Z INFO  fentry_fork] New process is created by: 12345 child id: 67890
```

<!-- markdownlint-enable MD013 -->
