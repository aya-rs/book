# Cross-compiling aya-based programs

The instructions below are for cross-compiling aya eBPF programs
on Macs. The Windows instructions are on the _TODO_ list - contributions are welcome!

# Cross-compiling aya-based programs on Mac
Cross-compilation should work both on the Intel and M1/M2 Macs.

1. Install `rustup` following the instructions on https://rustup.rs/.
2. Install a rust stable toolchain: `rustup install stable`
3. Install a rust nightly toolchain: `rustup toolchain install nightly --component rust-src`
4. `brew install llvm`.
5. `brew install FiloSottile/musl-cross/musl-cross`
6. Install bpf-linker with `--no-default-features`:<br>
`cargo install bpf-linker --no-default-features`.<br>
This should work if `llvm-config` is found in the PATH.  If needed, you can also try:
`LLVM_SYS_160_PREFIX=$(brew --prefix llvm) cargo install bpf-linker --no-default-features`
7. Build BPF object files: `cargo xtask build-ebpf [--release]`
8. Build the userspace code. `'-C link-arg=-s'` flag is optional - used to produce a smaller executable file.<br>
`RUSTFLAGS="-Clinker=x86_64-linux-musl-ld -C link-arg=-s" cargo build --release --target=x86_64-unknown-linux-musl`<br>
The cross-compiled program `target/x86_64-unknown-linux-musl/release/<program_name>` can be copied to a Linux server or VM (having a capable kernel) and run there.  Don't forget `sudo` if you are not `root`!