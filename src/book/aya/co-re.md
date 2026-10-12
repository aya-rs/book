# Kernel Portability with CO-RE

BPF CO-RE (Compile Once, Run Everywhere) enables eBPF programs to adapt to
differences in kernel type layouts at load time. For an introduction to its
design and components, see Andrii Nakryiko's [BPF CO-RE overview][co-re-overview].
This chapter covers [CO-RE support in Rust and Aya](co-re/support.md) and a
practical workflow for using [Rust with C shims](co-re/rust-with-c-shims.md).

[co-re-overview]: https://nakryiko.com/posts/bpf-portability-and-co-re/
