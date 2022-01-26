# Hello XDP!

## Example Project

While there are myriad trace points to attach to and program types to write we should start somewhere simple.

XDP (eXpress Data Path) programs permit our eBPF program to make decisions about packets that have been received on the interface to which our program is attached. To keep things simple, we'll build a very simplistic firewall to permit or deny traffic.

## eBPF Component

### Permit All

We must first write the eBPF component of our program.
The logic for this program is located in `myapp-ebpf/src/main.rs` and currently looks like this:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp-ebpf/src/main.rs:all}}
```

- `#![no_std]` is required since we cannot use the standard library.
- `#![no_main]` is required as we have no main function.
- The `#[panic_handler]` is required to keep the compiler happy, although it is never used since we cannot panic.

This is a minimal generated XDP program that permits all traffic.

Let's look at some of its details.
First we make some `use` declarations:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp-ebpf/src/main.rs:use }}
```

Then our application logic:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp-ebpf/src/main.rs:main }}
```

- `#[xdp(name="myapp")]` indicates that this function is an XDP program.
- The `try_myapp` function returns a Result that currenlty permits all traffic.
- The `myapp` program calls `try_myapp` and handles any errors by returning `XDP_ABORTED`, which will drop the packet and raise a tracepoint exception.

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

The generated application has the following content:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp/src/main.rs:all }}
```

Let's look at the details of this program.

There is a dependency on `tokio` added to `myapp/Cargo.toml` - `tokio`
provides the [Ctrl-C handler](https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html) functionality and will also come useful later when we
expand the functionality of the initial program:
```toml
{{#include ../../examples/myapp-01/myapp/Cargo.toml:15}}
```

The following `use` declarations are added at the top of the `myapp/src/main.rs`:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp/src/main.rs:use }}
```


The async main function loads and runs our program:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-01/myapp/src/main.rs:tokiomain }}
```


The program optionally takes an argument for the interface we wish to attach it to (defaults to `eth0`).

`include_bytes_aligned!` copies the contents of the BPF object file
into a variable at the compile time.
The statement `let mut bpf = Bpf::load_file(data)?;`:
- Reads the ELF contents
- Creates any maps
- If your system supports BPF Type Format (BTF), it will read the current BTF description and performs any necessary relocations

Once our file is loaded, we can extract the XDP program with `let program: &mut Xdp = bpf.program_mut("myapp")?.try_into()?;` and then load it in to the kernel with `program.load()`.

Finally, we can attach it to an interface with `program.attach(&opt.iface, XdpFlags::default())?;`.  As the error message indicates, it is possible to use
`XdpFlags::SKB_MODE` instead of `XdpFlags::default()` as the second argument for
`program.attach` if the default attachment mode is not supported.

Let's try it out!

```console
# change directory to the root or myapp
$ cargo build
$ cargo xtask run -- -h
myapp 0.1.0

USAGE:
    myapp [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --iface <iface>     [default: eth0]

# add -i or --iface parameter if need to attach to an interface other than eth0
# - for example, cargo xtask run -- -i wlp2s0
$ cargo xtask run
10:58:21 [INFO] myapp: [myapp/src/main.rs:51] Waiting for Ctrl-C...
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
        loaded_at 2022-01-07T12:17:54+0000  uid 0
        xlated 16B  jited 18B  memlock 4096B
        pids myapp(69184)
```

Running the command again once `myapp` has exited will show that the program is no longer running.
