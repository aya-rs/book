# Fentry / Fexit

> [!NOTE]
> Full code for the example in this chapter is available [on GitHub][source-code].

## What are fentry and fexit programs?

Fentry and fexit programs attach to the entry and exit of a kernel function
through a [BPF trampoline][bpf-trampoline]. Compared to kprobes, they have
lower overhead and, because they are BTF-aware, they let the verifier reason
about kernel types directly — so kernel pointers can be dereferenced without
calling `bpf_probe_read_kernel`. A fexit program also has access to the
function's return value in the same context, without needing a separate
return-side program the way kprobes do with kretprobes.

> [!NOTE]
> Fentry and fexit require a kernel built with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
> and a kernel version of at least 5.5.

## Example project

To illustrate fentry and fexit with Aya, let's write a program which attaches
to [`kernel_clone`][kernel-clone] — the function the kernel uses to create new
processes and threads — and prints the PID of the caller on entry and the PID
of the newly created child on exit.

## Design

For this demo program, we are going to rely on aya-log to print PIDs from the
BPF program.

The `kernel_clone` function is also called for thread creation, so to keep the
output focused on process creation we filter out callers that pass the
`CLONE_THREAD` flag.

## eBPF code

- From the `kernel_clone` signature, we see that `struct kernel_clone_args
  *args` is the only function parameter. We access it from the `FEntryContext`
  / `FExitContext` handles via `ctx.arg(0)`.
- Because fentry/fexit programs run inside a BPF trampoline, the verifier
  treats the argument pointer as a typed kernel pointer and we can dereference
  it directly — no `bpf_probe_read_kernel` call is required.
- In the fexit program, the return value of `kernel_clone` (the child PID) is
  exposed as the slot after the original arguments, so we read it with
  `ctx.arg(1)`.
- We check the `flags` field for `CLONE_THREAD`, and for process-creating
  calls we print the parent PID (and, on exit, the child PID) using the
  aya-log `info!` macro.

Here's how the eBPF code looks like:

```rust,ignore
{{#include ../../../examples/fentry-fork/fentry-fork-ebpf/src/main.rs}}
```

## Userspace code

The purpose of the userspace code is to load the eBPF program and attach the
fentry and fexit handlers to `kernel_clone`. Both program types need a
[`Btf`][aya-btf] handle: `Btf::from_sys_fs()` reads the running kernel's BTF
from `/sys/kernel/btf/vmlinux`, aya uses it to translate the function name
to its BTF type id, and the kernel uses that id to find the function's
address and signature, so it can build a trampoline and verify your
argument accesses.

Here's how the code looks like:

```rust,ignore
{{#include ../../../examples/fentry-fork/fentry-fork/src/main.rs}}
```

## Running the program

<!-- markdownlint-disable MD013 -->

```console
$ RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
[2026-05-07T10:00:00Z INFO  fentry_fork] Waiting for Ctrl-C...
[2026-05-07T10:00:05Z INFO  fentry_fork] Process creation is started by: 12345
[2026-05-07T10:00:05Z INFO  fentry_fork] New process is created by: 12345 child id: 67890
```

<!-- markdownlint-enable MD013 -->

[source-code]: https://github.com/aya-rs/book/tree/main/examples/fentry-fork
[bpf-trampoline]: https://docs.ebpf.io/linux/concepts/trampolines/
[kernel-clone]: https://github.com/torvalds/linux/blob/v7.0/kernel/fork.c#L2612
[aya-btf]: https://docs.rs/aya/latest/aya/struct.Btf.html
