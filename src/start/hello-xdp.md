# Hello XDP!

## Example Project

While there are myriad trace points to attach to and program types to write we should start somewhere simple.

XDP (eXpress Data Path) programs permit our eBPF program to make decisions about packets that have been received on the interface to which our program is attached. To keep things simple, we'll build a very simplistic firewall to permit or deny traffic.

## eBPF Component

### Permit All

We must first write the eBPF component of our program.
The logic for this program is located in `myapp-ebpf/src/main.rs` and currently looks like this:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-00/myapp-ebpf/src/main.rs}}
```

- `#![no_std]` is required since we cannot use the standard library.
- `#![no_main]` is required as we have no main function.
- The `#[panic_handler]` is required to keep the compiler happy, although it is never used since we cannot panic.

Let's expand this by adding an XDP program that permits all traffic.

First we'll make some use declarations:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp-ebpf/src/main.rs:use }}
```

Then our application logic:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp-ebpf/src/main.rs:main }}
```

- `#[xdp]` indicates that this function is an XDP program
- The `try_xdp_firewall` function returns a Result that permits all traffic
- The `xdp_firewall` program calls `try_xdp_firewall` and handles any errors by returning `XDP_ABORTED`, which will drop the packet and raise a tracepoint exception.

Now we can compile this using `cargo xtask build-ebpf`

### Verifying The Program

Let's take a look at the compiled eBPF program:

```console
$ llvm-objdump -S target/bpfel-unknown-none/debug/myapp

target/bpfel-unknown-none/debug/myapp:  file format elf64-bpf


Disassembly of section xdp:

0000000000000000 <xdp_firewall>:
       0:       b7 00 00 00 02 00 00 00 r0 = 2
       1:       95 00 00 00 00 00 00 00 exit
```

We can see an `xdp_firewall` section here.
`r0 = 2` sets register `0` to `2`, which is the value of the `XDP_PASS` action.
`exit` ends the program.

Simple!

## User-space Component

Now our eBPF program is complete and compiled, we need a user-space program to load it and attach it to a trace point.
Fortunately, we have a program ready in `myapp/src/main.rs` which is going to do that for us.

### Starting Out

The generated application has the following content:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-00/myapp/src/main.rs }}
```

Let's adapt it to load our program.

We will add a dependency on `ctrlc` to `myapp/Cargo.toml`:
```toml
{{#include ../../examples/myapp-01/myapp/Cargo.toml:11}}
```

Add the following declarations at the top of the `myapp/src/main.rs`:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp/src/main.rs:use }}
```

Then we'll adapt the `try_main` function to load our program:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp/src/main.rs:try_main }}
```

The program takes two positional arguments
- The path to our eBPF application
- The interface we wish to attach it to (defaults to `eth0`)

The line `let mut bpf = Bpf::load_file(&path)?;`:
- Opens the file
- Reads the ELF contents
- Creates any maps
- If your system supports BPF Type Format (BTF), it will read the current BTF description and performs any necessary relocations

Once our file is loaded, we can extract the XDP probe with `let probe: &mut Xdp = bpf.program_mut("xdp")?.try_into()?;` and then load it in to the kernel with `probe.load()`.

Finally, we can attach it to an interface with `probe.attach(&iface, XdpFlags::default())?;`

Let's try it out!

```console
$ cargo build
$ sudo ./target/debug/myapp --path ./target/bpfel-unknown-none/debug/myapp wlp2s0
Waiting for Ctrl-C...
Exiting...
```

That was uneventful. Did it work?

> 💡 **HINT: Error Loading Program?**
>
> If you get an error loading the program, try changing `XdpFlags::default()` to `XdpFlags::SKB_MODE`

### The Lifecycle of an eBPF Program

The program runs until CTRL+C is pressed and then exits.
On exit, Aya takes care of detaching the program for us.

If you issue the `sudo bpftool prog list` command when `myapp` is running you can verify that it is loaded:

```console
84: xdp  tag 3b185187f1855c4c  gpl
        loaded_at 2021-08-05T13:35:06+0100  uid 0
        xlated 16B  jited 18B  memlock 4096B
        pids myapp(69184)
```

Running the command again once `myapp` has exited will show that the program is no longer running.
