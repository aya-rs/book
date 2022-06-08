# Hello XDP!

!!! example "Source Code"

    Full code for the example in this chapter is availble [here](https://github.com/aya-rs/book/tree/main/examples/myapp-01)

## Example Project

While there are myriad trace points to attach to and program types to write we should start somewhere simple.

XDP (eXpress Data Path) programs permit our eBPF program to make decisions about packets that have been received on the interface to which our program is attached. To keep things simple, we'll build a very simplistic firewall to permit or deny traffic.

## eBPF Component

### Permit All

We must first write the eBPF component of our program.
This is a minimal generated XDP program that permits all traffic.
The logic for this program is located in `myapp-ebpf/src/main.rs` and currently looks like this:

```rust linenums="1" title="myapp-ebpf/src/main.rs"
--8<-- "examples/myapp-01/myapp-ebpf/src/main.rs"
```

1. `#![no_std]` is required since we cannot use the standard library.
2. `#![no_main]` is required as we have no main function.
3. The `#[panic_handler]` is required to keep the compiler happy, although it is never used since we cannot panic.
4. This indicates that this function is an XDP program.
5. Our main entry point defers to another function and performs error handling, returning `XDP_ABORTED`, which will drop the packet.
6. This function returns a `Result` that permits all traffic.

Now we can compile this using `cargo xtask build-ebpf`.

### Verifying The Program

Let's take a look at the compiled eBPF program:

```console
$ llvm-objdump -S target/bpfel-unknown-none/debug/myapp

target/bpfel-unknown-none/debug/myapp:  file format elf64-bpf


Disassembly of section xdp/myapp:

0000000000000000 <myapp>:
       0:       b7 00 00 00 02 00 00 00 r0 = 2
       1:       95 00 00 00 00 00 00 00 exit
```

We can see an `xdp/myapp` section here.
`r0 = 2` sets register `0` to `2`, which is the value of the `XDP_PASS` action.
`exit` ends the program.

Simple!

## User-space Component

Now our eBPF program is complete and compiled, we need a user-space program to load it and attach it to a trace point.
Fortunately, we have a generated program ready in `myapp/src/main.rs` which is going to do that for us.

### Starting Out

Let's look at the details of our generated user-space application:

```rust linenums="1" title="myapp/src/main.rs"
--8<-- "examples/myapp-01/myapp/src/main.rs"
```

1. `tokio` is the async library we're using, which provides our [Ctrl-C handler](https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html). It will come in useful later as we expand the functionality of the initial program:
2. Here we declare our CLI flags. Just `--iface` for now for passing the interface name
3. Here's our main entry point
4. This copies the contents of the BPF ELF object file into a variable at the compile time.
5. This reads the BPF ELF object file contents, creates any maps, performs BTF relocations
6. We extract the XDP program
7. And then load it in to the kernel
8. Finally, we can attach it to an interface

Let's try it out!

```console
$ cargo xtask run -- -h
myapp 0.1.0

USAGE:
    myapp [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --iface <iface>     [default: eth0]
```

!!! note "Interface Name"

    This command assumes the interface is `eth0` by default. If you wish to attach to an interface
    with another name, use `cargo xtask run -- --iface wlp2s0`, where  `wlp2s0` is your interface.

```console
$ cargo xtask run
10:58:21 [INFO] myapp: [myapp/src/main.rs:51] Waiting for Ctrl-C...
Exiting...
```

That was uneventful. Did it work?

!!! bug "Error Loading Program?"

    If you get an error loading the program, try changing `XdpFlags::default()` to `XdpFlags::SKB_MODE`


### The Lifecycle of an eBPF Program

The program runs until CTRL+C is pressed and then exits.
On exit, Aya takes care of detaching the program for us.

If you issue the `sudo bpftool prog list` command when `myapp` is running you can verify that it is loaded:

```console
84: xdp  tag 3b185187f1855c4c  gpl
        loaded_at 2022-01-07T12:17:54+0000  uid 0
        xlated 16B  jited 18B  memlock 4096B
        pids myapp(69184)
```

Running the command again once `myapp` has exited will show that the program is no longer running.
