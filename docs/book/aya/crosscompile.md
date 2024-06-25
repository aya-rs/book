# Cross-compiling aya-based programs

The instructions below show how to cross compile aya eBPF programs on Macs.
Cross compiling on other systems is possible too and we're going
to add instructions to do that soon (PRs welcome!).

# Cross-compiling aya-based programs on Mac

Cross compilation should work on both Intel and Apple Silicon Macs.

1. Install `rustup` following the instructions on <https://rustup.rs/>
1. Install the stable and nightly rust toolchains:
```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```
1. Install the [rustup target](https://doc.rust-lang.org/nightly/rustc/platform-support.html#tier-1-with-host-tools) for your Linux target platform:
```bash
ARCH=x86_64
rustup target add ${ARCH}-unknown-linux-musl
```
1. Install LLVM with brew:
```bash
brew install llvm
```

1. Install the musl cross compiler:  
to cross-compile for only `x86_64` targets (the default in musl-cross):
```bash
brew install FiloSottile/musl-cross/musl-cross
```
to cross-compile for only `aarch64` targets:
```bash
brew install FiloSottile/musl-cross/musl-cross --without-x86_64 --with-aarch64
```
to cross-compile for both `x86_64` and `aarch64` targets:
```bash
brew install FiloSottile/musl-cross/musl-cross --with-aarch64
```
See [homebrew-musl-cross](https://github.com/FiloSottile/homebrew-musl-cross)
for additional platform-specific options.

1. Install bpf-linker. Change the version number in `LLVM_SYS_<version>_PREFIX` to correspond
to the major version of the [llvm-sys](https://crates.io/crates/llvm-sys) crate:

```bash
LLVM_SYS_180_PREFIX=$(brew --prefix llvm) cargo install bpf-linker --no-default-features
```
1. Build BPF object files:
```bash
cargo xtask build-ebpf --release
```
1. Build the userspace code:
```bash
RUSTFLAGS="-Clinker=${ARCH}-linux-musl-ld" cargo build --release --target=${ARCH}-unknown-linux-musl
```
The cross-compiled program  
`target/${ARCH}-unknown-linux-musl/release/<program_name>`  
can be copied to a Linux server or VM and run there.
