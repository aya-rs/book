# Tracepoints

> [!NOTE]
> Full code for the example in this chapter is available [on GitHub][source-code].

## What are Tracepoints in eBPF?

Tracepoints are static probing points inserted at specific locations in the
Linux kernel source code.
They provide a stable and efficient way to monitor kernel events without the
overhead of dynamic tracing methods like kprobes.

Common tracepoint categories include:

- System calls (`syscalls`)
- Scheduler events (`sched`)
- Network events (`net`)
- File system events (`vfs`)

The available events are listed under `/sys/kernel/tracing/events` or can be
enumerated with `bpftrace`, e.g.:

```shell
sudo bpftrace -l 'tracepoint:syscalls:sys_enter_*'
```

## Example project

Let's create a tracepoint program that monitors system calls using the
`sys_enter_execve` tracepoint, which fires when a new process is executed.

## Design

We're going to:

- Create a tracepoint program that attaches to `sys_enter_execve`
- Use a per-CPU array buffer to read the filename from userspace
- Log the command name and filename being executed

## eBPF code

The eBPF program will read the filename from the tracepoint context and log
information about the execve system call:

```rust,ignore
{{#include ../../../examples/tracepoint/tracepoint-ebpf/src/main.rs}}

```

Key points in the eBPF code:

1. **Per-CPU Buffer**: We use `PerCpuArray<Buf>` to store the filename string,
   as the amount of available stack size is very limited.
2. **Context Reading**: The filename is read from a specific offset in the
   tracepoint context (offset 16 for `sys_enter_execve`).
   The format of the context can be extracted from the file
   `/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format`.
3. **Userspace Memory**: We use `bpf_probe_read_user_str_bytes` to safely read
   the filename string from userspace memory
4. **Logging**: We log both the command name and filename using the `info!` macro

## Userspace code

The userspace code loads the eBPF program and attaches it to the tracepoint:

```rust,ignore
{{#include ../../../examples/tracepoint/tracepoint/src/main.rs}}
```

Steps in the userspace code:

1. **Memory Limit**: Remove the memlock limit for older kernels
2. **Load Program**: Load the compiled eBPF object file
3. **Logger Setup**: Initialize the eBPF logger to receive log messages
4. **Attach Tracepoint**: Attach the program to the `syscalls/sys_enter_execve`
   tracepoint
5. **Signal Handling**: Wait for Ctrl-C to exit gracefully

## Running the program

```console
$ cargo run
[INFO  tracepoint] Tracepoint sys_enter_execve called by: zsh, filename: /usr/bin/git
[INFO  tracepoint] Tracepoint sys_enter_execve called by: zsh, filename: /usr/bin/wc
[INFO  tracepoint] Tracepoint sys_enter_execve called by: zsh, filename: /usr/bin/tail
[INFO  tracepoint] Tracepoint sys_enter_execve called by: zsh, filename: /usr/bin/ls
```

The program will now log every new process execution on the system,
showing which command started the process and what binary is being executed.

[source-code]: https://github.com/aya-rs/book/tree/main/examples/tracepoint
