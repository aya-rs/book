# Development Environment

## Prerequisites

Before getting started you will need the Rust stable and nightly tool-chains installed on your system.
This is easily achieved with [`rustup`](https://rustup.rs):

```console
rustup install stable
rustup toolchain install nightly --component rust-src
```

Once you have the Rust tool-chains installed, you must also install the `bpf-linker` - for linking our eBPF program - and `cargo-generate` - for generating the project skeleton.

```console
cargo +nightly install bpf-linker
cargo install --git http://github.com/cargo-generate/cargo-generate cargo-generate
```

If you don't have and don't want to install LLVM, you can use rust-llvm feature:
```console
cargo install --git https://github.com/aya-rs/bpf-linker  --tag v0.9.2 --no-default-features --features rust-llvm -- bpf-linker
```

## Starting A New Project

To start a new project, you can use `cargo-generate`:

```console
cargo generate https://github.com/aya-rs/aya-template
```

This will prompt you for a project name, a type of eBPF program, and possibly for other
choices depending on the eBPF program (for example, the 'attach direction: Ingress or Egress'
for the classifier type. You can add those options to the `cargo generate` command, for example:
```console
cargo generate --name xdpfw -d program_type=xdp https://github.com/aya-rs/aya-template
```
or
```console
cargo generate --name tcfw -d program_type=classifier -d direction=Ingress https://github.com/aya-rs/aya-template
```

See https://github.com/aya-rs/aya-template/blob/main/cargo-generate.toml for the full list of available options.


We'll be using the `myapp` name for the next examples.
