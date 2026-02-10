# Development Environment

## Prerequisites

Before getting started you will need the Rust stable and nightly toolchains
installed on your system.  This is easily achieved with
[`rustup`](https://rustup.rs):

```console
rustup install stable
rustup toolchain install nightly --component rust-src
```

Once you have the Rust toolchains installed, you must also install `bpf-linker`.
Because the required LLVM version and platform-specific steps change over time,
follow the installation instructions in the [`bpf-linker` README][bpf-linker-readme].

To generate the scaffolding for your project, you're going to need
`cargo-generate`, which you can install following [these
instructions][cargo-generate-install].

And finally to generate bindings for kernel data structures, you must install
`bpftool`, either from your distribution or building it from
[source](https://github.com/libbpf/bpftool).

> [!WARNING]
> If you're running on Ubuntu 20.04, there is a bug with bpftool and the
> default kernel installed by the distribution. To avoid running into it, you
> can install a newer bpftool version that does not include the bug with:
>
> ```console
> sudo apt install linux-tools-5.8.0-63-generic
> export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
> ```

## Starting A New Project

To start a new project, you can use `cargo-generate`:

```console
cargo generate https://github.com/aya-rs/aya-template
```

This will prompt you for a project name - we'll be using `myapp` in this
example. It will also prompt you for a program type and possibly other options
depending on the chosen type (for example, the attach direction for network
classifiers).

If you prefer, you can set template options directly from the command line, eg:

```console
cargo generate --name myapp -d program_type=xdp https://github.com/aya-rs/aya-template
```

See [the cargo-generate.toml file (in the aya-template repository)][cargo-generate-toml]
for the full list of available options.

[cargo-generate-toml]: https://github.com/aya-rs/aya-template/blob/main/cargo-generate.toml

[cargo-generate-install]: https://cargo-generate.github.io/cargo-generate/installation.html

[bpf-linker-readme]: https://github.com/aya-rs/bpf-linker#installation
