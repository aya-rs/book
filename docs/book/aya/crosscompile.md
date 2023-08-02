# Cross-compiling aya-based programs

The instructions below show how to cross compile aya eBPF programs on Macs.
Cross compiling on other systems is possible too and we're going
to add instructions to do that soon (PRs welcome!).

# Cross-compiling aya-based programs on Mac

Cross compilation should work on both Intel and Apple Silicon Macs.

1. Install `rustup` following the instructions on <https://rustup.rs/>
2. Install a rust stable toolchain: `rustup install stable`
3. Install a rust nightly toolchain:  
`rustup toolchain install nightly --component rust-src`
4. `brew install llvm`
5. `brew install FiloSottile/musl-cross/musl-cross`
6. Install bpf-linker:  
`LLVM_SYS_160_PREFIX=$(brew --prefix llvm) cargo install bpf-linker --no-default-features`
7. Build BPF object files: `cargo xtask build-ebpf --release`
8. Build the userspace code:  
```bash
RUSTFLAGS="-Clinker=x86_64-linux-musl-ld" cargo build --release
--target=x86_64-unknown-linux-musl
```
The cross-compiled program  
`target/x86_64-unknown-linux-musl/release/<program_name>`
can be copied to a Linux server or VM and run there.