# Tracepoints

!!! example "Source Code"

    Full code for the example in this chapter is available [here](https://github.com/aya-rs/book/tree/main/examples/tracepoint-openat).

## What are the tracepoint in eBPF?

The tracepoint BPF programs attach to kernel functions and are able to access the function parameters of those functions.  You can find more information about tracepoint in the [kernel documentation](https://docs.kernel.org/trace/tracepoints.html), tracepoint is more stable than kprobe.

## Example project

To illustrate tracepoints with Aya, let's write a program which attaches a eBPF handler to the [`sys_openat`](https://elixir.bootlin.com/linux/latest/source/include/linux/syscalls.h#L472) syscall and allows printing the filename from the function parameter.

## Design

For this demo program, we are going to rely on `bpf_printk` macro to print filename from the BPF program and not going to have any custom BPF maps (besides those created by aya-log).

## eBPF code

* We can see the `sys_openat` signature in `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format` (attach at the enter of function).
* We call `read_at` method of `TracePointContext` struct to get the filename pointer at the offset.
* We print the filename using aya_bpf `bpf_printk` macro.

Here's how the eBPF code looks like:

```rust linenums="1" title="tracepoint-openat-ebpf/src/main.rs"
--8<-- "examples/tracepoint-openat/tracepoint-openat-ebpf/src/main.rs"
```

## Userspace code

The purpose of the userspace code is to load the eBPF program and attach it to the
`sys_enter_openat` trace point.

Here's how the code looks like:

```rust linenums="1" title="tracepoint-openat/src/main.rs"
--8<-- "examples/tracepoint-openat/tracepoint-openat/src/main.rs"
```

## Running the program

```shell
$ RUST_LOG=info cargo xtask run --release
[2023-05-03T09:02:02Z INFO  tracepoint_openat] Waiting for Ctrl-C...
[2023-05-03T09:02:02Z INFO  tracepoint_openat] tracepoint sys_enter_openat called
[2023-05-03T09:02:02Z INFO  tracepoint_openat] tracepoint sys_enter_openat called
[2023-05-03T09:02:02Z INFO  tracepoint_openat] tracepoint sys_enter_openat called
[2023-05-03T09:02:02Z INFO  tracepoint_openat] tracepoint sys_enter_openat called
```

The output of `bpf_printk` macro can be read by executing the following command in a second terminal:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
 gsd-housekeepin-1478    [001] d...1  9222.088146: bpf_trace_printk: file_name: /etc/fstab
 gsd-housekeepin-1478    [001] d...1  9222.088222: bpf_trace_printk: file_name: /proc/self/mountinfo
 gsd-housekeepin-1478    [001] d...1  9222.088441: bpf_trace_printk: file_name: /run/mount/utab
 gsd-housekeepin-1478    [001] d...1  9222.088592: bpf_trace_printk: file_name: /proc/self/mountinfo
```
