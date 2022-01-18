# Development Environment

## Prerequisites

Before getting started you will need the Rust stable and nightly toolchains installed on your system. (The nightly toolchain is needed to use the bpf-linker installed in the next step.)
This is easily achieved with [`rustup`](https://rustup.rs):

```console
rustup install stable
rustup toolchain install nightly --component rust-src
```

Once you have the Rust toolchains installed, you must also install the `bpf-linker` - for linking our eBPF program - and `cargo-generate` - for generating the project skeleton.

```console
cargo install bpf-linker
cargo install --git http://github.com/cargo-generate/cargo-generate cargo-generate
```

If you have LLVM installed and want to use it instead of rust-llvm, you can use the system-llvm feature:
```console
cargo install --git https://github.com/aya-rs/bpf-linker  --tag v0.9.3 --no-default-features --features system-llvm -- bpf-linker
```

## Starting A New Project

To start a new project, you can use `cargo-generate`:

```console
cargo generate https://github.com/aya-rs/aya-template
```
This will prompt you for a project name - we'll be using `myapp` in this example. It will also prompt you for a program type and possibly other options depending on the chosen type (for example, the attach direction for network classifiers).

If you prefer, you can set template options directly from the command line:
```console
cargo generate --name xdpfw -d program_type=xdp https://github.com/aya-rs/aya-template
```
or
```console
cargo generate --name tcfw -d program_type=classifier -d direction=Ingress https://github.com/aya-rs/aya-template
```

See https://github.com/aya-rs/aya-template/blob/main/cargo-generate.toml for the full list of available options.
