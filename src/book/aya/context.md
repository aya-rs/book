# Reading Values From A Context

In the Linux kernel, every eBPF program receives a single opaque pointer at its
entry point in the `R1` register. What that pointer points to is dictated
by the program type. Aya wraps this pointer in a type-safe `Context` struct
specific to each program type.  

There is no universal Context type in eBPF, so the data that you
extract—and how you extract it—depends on the specific program type and hook
that you are attaching to. However, access patterns do generally fall into a
few core categories:

---

## 1. The Universal Base: `EbpfContext`

Most context types in Aya implement the
[`EbpfContext`](https://docs.rs/aya-ebpf/latest/aya_ebpf/trait.EbpfContext.html)
trait. This provides universal access to common process metadata via kernel
helpers for any program type whose context implements `EbpfContext`.

```rust,ignore
use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    EbpfContext,
};

#[kprobe]
pub fn my_probe(ctx: ProbeContext) -> u32 {
    // In the Linux kernel:
    // - `pid` is the kernel thread ID (TID)
    // - `tgid` is the thread group ID (user-space PID)
    let tid = ctx.pid();
    let pid = ctx.tgid();
    let uid = ctx.uid();
    let gid = ctx.gid();

    // Grabbing the process name (TASK_COMM_LEN is 16 bytes):
    if let Ok(comm) = ctx.command() {
        // comm is [u8; 16]
    }

    0
}
```

---

## 2. Networking Memory Bounds (`XdpContext`, `TcContext`)

Networking programs work directly on raw packet memory buffers.
Rather than exposing arbitrary fields, contexts like `XdpContext` and
`TcContext` provide metadata accessors alongside pointers to the
beginning (`data()`) and end (`data_end()`) of the packet payload.

For a hands-on walkthrough of bounds-checking and packet parsing using
`XdpContext`, see [Parsing Packets](../start/parsing-packets.md).

---

## 3. Offset-Based Reads: `TracePointContext`

Tracepoints receive memory buffers formatted according to kernel-defined
schemas rather than static C structures. To read values from`TracePointContext`,
inspect the event format in the Linux tracing subsystem:

```bash
cat /sys/kernel/tracing/events/sched/sched_process_exec/format
```

Once you identify the byte offset and type of the target field, use
`ctx.read_at::<T>(offset)`:

```rust,ignore
use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

// In /sys/kernel/tracing/events/sched/sched_process_exec/format,
// 'common_pid' sits at offset 16 as a 4-byte integer:
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    // read_at::<T> requires an offset and is unsafe because it reads raw
    // context memory
    let pid: u32 = match unsafe { ctx.read_at(16) } {
        Ok(val) => val,
        Err(_) => return 1,
    };

    0
}
```

---

## 4. Argument Extraction: BTF (`FEntryContext`) vs Legacy (`ProbeContext`)

Extracting function arguments differs fundamentally depending on whether your
program runs through the modern BPF trampolines or legacy probe registers.

### Modern Trampolines (`FEntryContext`)

In BTF-enabled hooks like `fentry`, the kernel verifier understands the
target function's exact signature. Arguments can be retrieved by index via
`ctx.arg(n)`. Because verifier possesses full type information,
kernel pointers can be dereferenced directly without manual copy helpers:

```rust,ignore
use aya_ebpf::{
    macros::fentry,
    programs::FEntryContext,
};

// Hooking: int do_unlinkat(int dfd, struct filename *name)
#[fentry(function = "do_unlinkat")]
pub fn do_unlinkat(ctx: FEntryContext) -> u32 {
    // Arguments are 0-indexed:
    let dfd: i32 = ctx.arg(0);

    // arg(1) is a pointer to `struct filename`.
    // With BTF, typed pointers can be passed around and dereferenced directly.
    let name_ptr: *const u8 = ctx.arg(1);

    0
}
```

### Legacy Probes (`ProbeContext`)

For classic `kprobes` and `uprobes`, arguments are extracted directly from CPU
architecture registers. `ctx.arg(n)` returns an `Option<T>`, and raw pointer
targets cannot be dereferenced; attempting to do so will cause the eBPF
verifier to reject the program. You must read the memory into an eBPF-allocated
buffer using helper functions like `bpf_probe_read_kernel()`:

```rust,ignore
use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe]
pub fn do_unlinkat(ctx: ProbeContext) -> u32 {
    let dfd: i32 = match ctx.arg(0) {
        Some(val) => val,
        None => return 1,
    };

    let name_ptr: *const u8 = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return 1,
    };

    // The verifier forbids direct dereferencing (*name_ptr).
    // You must copy the kernel memory into an eBPF buffer via a helper:
    let mut buffer = [0u8; 64];
    let _ = unsafe { 
        bpf_probe_read_kernel(name_ptr as *const _, &mut buffer)
    };

    0
}
```

---

## 5. Reading Return Values: BTF (`FExitContext`) vs Legacy (`RetProbeContext`)

Extracting the return value of a kernel function presents the same
BTF-vs-legacy divide as argument extraction, but with a critical difference in
what context data is actually preserved.

### Modern Trampolines (`FExitContext`)

`fexit` programs run via BTF-enabled BPF trampolines. Because the kernel
preserves state across the function's execution, you get access to
**both the original arguments and the return value simultaneously**.

*Note: While `fexit` requires Linux 5.5+, reading the return value via
`FExitContext::ret()` requires Linux 5.17+.*

```rust,ignore
use aya_ebpf::{
    macros::fexit,
    programs::FExitContext,
};

// Hooking: int do_unlinkat(int dfd, struct filename *name)
#[fexit(function = "do_unlinkat")]
pub fn do_unlinkat_exit(ctx: FExitContext) -> u32 {
    // Original arguments are still accessible:
    let dfd: i32 = ctx.arg(0);

    // Grab the typed return value directly:
    let retval: i32 = ctx.ret();

    0
}
```

### Legacy Probes (`RetProbeContext`)

In a classic `kretprobe`, the probe fires *after* the target function has
already returned. The CPU registers that held the original function arguments
have been completely clobbered. You **only** have access to the return value,
which is pulled directly from the architecture's return register
(e.g., `RAX` on x86_64).

```rust,ignore
use aya_ebpf::{
    macros::kretprobe,
    programs::RetProbeContext,
};

#[kretprobe]
pub fn do_unlinkat_exit(ctx: RetProbeContext) -> u32 {
    // The original arguments are gone. You can only read the return value.
    // Because it is pulled from a raw CPU register, it returns an Option<T>.
    let retval: i32 = match ctx.ret() {
        Some(val) => val,
        None => return 1,
    };

    0
}
```
