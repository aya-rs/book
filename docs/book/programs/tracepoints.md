# Tracepoints

!!! example "Source Code"

    Full code for the example in this chapter is available [here](https://github.com/aya-rs/book/tree/main/examples/aya-tracepoint-echo-open). 
    
# What are the tracepoints in eBPF?

In the Linux kernel, tracepoints are 'hooks' which are left by the kernel developers, at predefined points in the code. These points are statically defined, in the sense that a given kernel provides these hooks, by default. One can provide code to be clasped with these hooks, and crucially, at _runtime_! If such a clasped code exists at a tracepoint, the kernel calls it. 

You can find more information about tracepoints in the [kernel documentation](https://docs.kernel.org/trace/tracepoints.html).

--------------------------------

Just as a side note: tracepoints are not exclusive to eBPF. The need for such hooks into the kernel was felt as far back as 2005, accordingly to this [article] (https://lwn.net/Articles/852112/). 

--------------------------------

How does one know which are these tracepoints? On a Ubuntu 22.04, running Linux kernel version 6.5.0-28-generic, the list is available by firing the command:

 `sudo cat   /sys/kernel/debug/tracing/available_events`

 The output looks like this:

```bash
.....
irq:softirq_exit
irq:softirq_entry
irq:irq_handler_exit
irq:irq_handler_entry
syscalls:sys_exit_capset
syscalls:sys_enter_capset
syscalls:sys_exit_capget
.....
```

There are 2180 events availble!

In order to avoid name collision, the pattern followed is "\<subsystem name\>:\<tracepoint name\>", as can be seen from the output above.

## Example project

To illustrate tracepoints using Aya, let's write a program which informs us whenever any file is opened by any process running in the system. 
The kernel tracepoint `syscalls:sys_openat` lets us do this. We will use `cargo generate` utility to build the template code structure:

```bash
cargo generate https://github.com/aya-rs/aya-template
 Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
 Project Name: aya-tracepoint-echo-open
 Destination: /home/nirmalya/Workspace-Rust/eBPF/my-second-ebpf/aya-tracepoint-echo-open ...
 project-name: aya-tracepoint-echo-open ...
 Generating template ...
✔  Which type of eBPF program? · tracepoint
 Which tracepoint category? (e.g sched, net etc...): syscalls
 Which tracepoint name? (e.g sched_switch, net_dev_queue): sys_enter_openat
 Moving generated files into: `<Current working directory>/aya-tracepoint-echo-open`...
 Initializing a fresh Git repository
 Done! New project created <Current working directory>/aya-tracepoint-echo-open
```

Note that the project's name is _aya-tracepoint-echo-open_, type of eBPF program is _tracepoint_ (from the menu), category is _syscalls_ and name of tracepoint is _sys_enter_openat_ .

The directory structure is similar to what is described [here](https://aya-rs.dev/book/start/#the-lifecycle-of-an-ebpf-program).

To build the application, move to the directory `aya-tracepoint-echo-open` and fire the following commands:

```bash
# First, build the application
cargo xtask build-ebp
# And, then run
RUST_LOG=info cargo xtask run
```

The output on the screen will be:

```bash
[2024-05-12T02:30:29Z INFO  aya_tracepoint_echo_open] Waiting for Ctrl-C...
[2024-05-12T02:30:29Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called
[2024-05-12T02:30:29Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called
[2024-05-12T02:30:29Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called
[2024-05-12T02:30:29Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called
....
```

So, the program is running but it is incomplete. We don't know which files are being opened. Let's modify the code, to see the names of those files.

## Design (attempt 1)

For this demo program, we are going to rely on aya-log to print filenames from the eBPF program. 

Because at the tracepoint `sys_enter_openat`, the kernel knows the name of the file (the path to the file, including relative path), we should be able to ask kernel to share that with us. Then, we can print the complete name of the file that is being opened.

For this to happen, such an approach will work:

```rust
// Source: aya-tracepoint-echo-open-ebpf/src/main.rs
const MAX_PATH: usize = 16;
// ....
#[tracepoint]
pub fn aya_tracepoint_echo_open(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint_echo_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_aya_tracepoint_echo_open(ctx: TracePointContext) -> Result<u32, i64> {

    let mut buf: [u8; MAX_PATH] = [0; MAX_PATH];

    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;
    if let Ok(filename_addr) = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) } {
       // read the filename
       let filename = unsafe {
            // Get an UTF-8 String from an array of bytes
            core::str::from_utf8_unchecked(
                    // Use the address of the kernel's string
                    // to copy its contents into the array named 'buf'  
                    match bpf_probe_read_user_str_bytes (
                        filename_addr as *const u8,
                        &mut buf,
                    ) {
                        Ok(_) =>  &buf,
                        Err(e)  => {
                            info!(&ctx, "tracepoint sys_enter_openat called buf_probe failed {}", e);
                            return Err(e);
                        }, 
                    }
            )

        };

        info!(&ctx, "tracepoint sys_enter_openat called, filename  {}", filename);  
    }
    Ok(0)
}
```

## eBPF code

- This is the code (its skeleton is generated by `aya-tool`) that runs in the Kernel's eBPF Virtual Machine. The pattern highlights how aya programs are structured: `aya_tracepoint_echo_open(ctx: TracePointContext)` is a public function; it delegates the actual eBPF task to a another function ( `try_aya_tracepoint_echo_open(ctx: TracePointContext) -> Result<u32, i64>`).
- The `TracePointContext` is one of goodies that Aya brings in. This works as a Rust-aware facade of the internal nuts and bolts that interact with the kernel's own APIs written in 'C'.
- The name of the file is a `string`  in 'C' (a null-terminated array of `char` s). To access that string, we need to have the address of the byte at the start of the string. The offset at which this address resides, is 24 according to the kernel's documentation (available through the `cat` command mentioned in the code block above). Using the context's `read_at()` function, the address is obtained and held in `filename_addr`. 
- The content of what `filename_addr` is pointing to, is copied into a byte-array held inside the function, as an UTF-8 string.
- Print the UTF-8 string.

It works. When run, the output is like this:

```console
$ RUST_LOG=info cargo xtask run
[2024-05-16T15:32:29Z INFO  aya_tracepoint_echo_open] Waiting for Ctrl-C...
[2024-05-16T15:32:30Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called, filename  /proc/meminfo
[2024-05-16T15:32:30Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called, filename  /sys/fs/cgroup/
[2024-05-16T15:32:30Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called, filename  /sys/fs/cgroup/
[2024-05-16T15:32:30Z INFO  aya_tracepoint_echo_open] tracepoint sys_enter_openat called, filename  /sys/fs/cgroup/
```

But the program is not designed correctly. Why? There are two reasons:

1.    The `buf` array is only of 16 bytes. The path-string of files being opened are likely to be much longer than this. The kernel accommodates 4096 bytes of path-string.

2.    It is not possible to hold 4096 bytes in the eBPF stack (the limit is 512 bytes). Therefore, we have to resort to some other mechanism to deal with this.

As it happens, _Aya_ provides a mechanism to do this, in the form of **eBPF Maps**. These maps are structured to accommodate data which are not bounded by the limit of 512 bytes. Moreover, these maps are a means to share data between eBPF programs and User-space programs. 

## Design (attempt 2)

Here's how the modified eBPF code looks like:

```rust linenums="1" title="aya-tracepoint-echo-open-ebpf/src/main.rs"
--8<-- "examples/aya-tracepoint-echo-open/aya-tracepoint-echo-open-ebpf/src/main.rs"
```

1.  The maximum length of path to the file being opened.
2.  A `struct` that encapsulates the space for holding the pathstring.
3.  The 'map' is created.
4.  The _buffer_ in the map is accessed.
5.  Contents of the bytes pointed to by `filename_addr` is copied.

The filename's length can be as long as 4K (4096) bytes and we can hold that in the map's own space. We are not bound by eBPF's stack-size limitation any more.

When run, the output is the same as earlier:

```console
$ RUST_LOG=info cargo xtask run 
[2024-05-17T10:13:16Z INFO  aya_tracepoint_echo_open] Waiting for Ctrl-C...
[2024-05-17T10:13:16Z INFO  aya_tracepoint_echo_open] Kernel tracepoint sys_enter_openat called,  filename /proc/33769/oom_score_adj
[2024-05-17T10:13:16Z INFO  aya_tracepoint_echo_open] Kernel tracepoint sys_enter_openat called,  filename /snap/firefox/4259/usr/lib/firefox/glibc-hwcaps/x86-64-v4/libmozsandbox.so
[2024-05-17T10:13:16Z INFO  aya_tracepoint_echo_open] Kernel tracepoint sys_enter_openat called,  filename /snap/firefox/4259/usr/lib/firefox/glibc-hwcaps/x86-64-v3/libmozsandbox.so
[2024-05-17T10:13:16Z INFO  aya_tracepoint_echo_open] Kernel tracepoint sys_enter_openat called,  filename /snap/firefox/4259/usr/lib/firefox/glibc-hwcaps/x86-64-v2/libmozsandbox.so
```

