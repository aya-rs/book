# Hello XDP

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [here][source-code].

## Example Project

While there are myriad trace points to attach to and program types to write we
should start somewhere simple.

XDP (eXpress Data Path) programs permit our eBPF program to make decisions
about packets that have been received on the interface to which our program is
attached. To keep things simple, we'll build a very simplistic firewall to
permit or deny traffic.

## eBPF Component

### Permit All

We must first write the eBPF component of our program.
This is a minimal generated XDP program that permits all traffic.
The logic for this program is located in `xdp-hello-ebpf/src/main.rs` and
currently looks like this:

```rust linenums="1" title="xdp-hello-ebpf/src/main.rs"
--8<-- "examples/xdp-hello/xdp-hello-ebpf/src/main.rs"
```

1. `#![no_std]` is required since we cannot use the standard library.
1. `#![no_main]` is required as we have no main function.
1. The `#[panic_handler]` is required to keep the compiler happy, although it
   is never used since we cannot panic.
1. This indicates that this function is an XDP program.
1. Our main entry point defers to another function and performs error handling,
   returning `XDP_ABORTED`, which will drop the packet.
1. Write a log entry every time a packet is received.
1. This function returns a `Result` that permits all traffic.

Now we can compile this using `cargo build`.

### Verifying The Program

Let's take a look at the compiled eBPF program:

<!-- markdownlint-disable MD010 -->

```console
$ llvm-objdump -S target/bpfel-unknown-none/debug/xdp-hello

target/bpfel-unknown-none/debug/xdp-hello:	file format elf64-bpf

Disassembly of section .text:

0000000000000000 <memset>:
        0:	15 03 06 00 00 00 00 00	if r3 == 0 goto +6 <LBB1_3>
        1:	b7 04 00 00 00 00 00 00	r4 = 0

0000000000000010 <LBB1_2>:
        2:	bf 15 00 00 00 00 00 00	r5 = r1
        3:	0f 45 00 00 00 00 00 00	r5 += r4
        4:	73 25 00 00 00 00 00 00	*(u8 *)(r5 + 0) = r2
        5:	07 04 00 00 01 00 00 00	r4 += 1
        6:	2d 43 fb ff 00 00 00 00	if r3 > r4 goto -5 <LBB1_2>

0000000000000038 <LBB1_3>:
        7:	95 00 00 00 00 00 00 00	exit

0000000000000040 <memcpy>:
        8:	15 03 09 00 00 00 00 00	if r3 == 0 goto +9 <LBB2_3>
        9:	b7 04 00 00 00 00 00 00	r4 = 0

0000000000000050 <LBB2_2>:
        10:	bf 15 00 00 00 00 00 00	r5 = r1
        11:	0f 45 00 00 00 00 00 00	r5 += r4
        12:	bf 20 00 00 00 00 00 00	r0 = r2
        13:	0f 40 00 00 00 00 00 00	r0 += r4
        14:	71 00 00 00 00 00 00 00	r0 = *(u8 *)(r0 + 0)
        15:	73 05 00 00 00 00 00 00	*(u8 *)(r5 + 0) = r0
        16:	07 04 00 00 01 00 00 00	r4 += 1
        17:	2d 43 f8 ff 00 00 00 00	if r3 > r4 goto -8 <LBB2_2>

0000000000000090 <LBB2_3>:
        18:	95 00 00 00 00 00 00 00	exit

Disassembly of section xdp/xdp_hello:

0000000000000000 <xdp_hello>:
        0:	bf 16 00 00 00 00 00 00	r6 = r1
        1:	b7 07 00 00 00 00 00 00	r7 = 0
        2:	63 7a fc ff 00 00 00 00	*(u32 *)(r10 - 4) = r7
        3:	bf a2 00 00 00 00 00 00	r2 = r10
:
        245:	18 03 00 00 ff ff ff ff 00 00 00 00 00 00 00 00	r3 = 4294967295 ll
        247:	bf 04 00 00 00 00 00 00	r4 = r0
        248:	b7 05 00 00 aa 00 00 00	r5 = 170
        249:	85 00 00 00 19 00 00 00	call 25

00000000000007d0 <LBB0_2>:
        250:	b7 00 00 00 02 00 00 00	r0 = 2
        251:	95 00 00 00 00 00 00 00	exit
```

<!-- markdownlint-enable MD010 -->

The output was trimmed for brevity.
We can see an `xdp/xdp_hello` section here.
And in `<LBB0_2>`, `r0 = 2` sets register `0` to `2`, which is the value of the
`XDP_PASS` action.
`exit` ends the program.

Simple!

## User-space Component

Now our eBPF program is complete and compiled, we need a user-space program to
load it and attach it to a trace point. Fortunately, we have a generated
program ready in `xdp-hello/src/main.rs` which is going to do that for us.

### Starting Out

Let's look at the details of our generated user-space application:

```rust linenums="1" title="xdp-hello/src/main.rs"
--8<-- "examples/xdp-hello/xdp-hello/src/main.rs"
```

1. `tokio` is the async library we're using, which provides our
   [Ctrl-C handler][ctrl-c-handler]. It will come in useful later as we expand
   the functionality of the initial program:
1. Here we declare our CLI flags. Just `--iface` for now for passing the
   interface name
1. Here's our main entry point
1. `include_bytes_aligned!()` copies the contents of the BPF ELF object file at
   the compile time
1. `Ebpf::load()` reads the BPF ELF object file contents from the output of the
   previous command, creates any maps, performs BTF relocations
1. We extract the XDP program
1. And then load it in to the kernel
1. Finally, we can attach it to an interface

Let's try it out!

```console
$ cargo run -- -h
    Finished dev [optimized] target(s) in 0.90s
    Finished dev [unoptimized + debuginfo] target(s) in 0.60s
xdp-hello

USAGE:
    xdp-hello [OPTIONS]

OPTIONS:
    -h, --help             Print help information
    -i, --iface <IFACE>    [default: eth0]
```

> [!NOTE] Interface Name
> This command assumes the interface is `eth0` by default. If you wish to
> attach to an interface with another name, use
>
> ```console
> RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- \
>   --iface wlp2s0
> ```
>
> where  `wlp2s0` is your interface.

```console
$ RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
[2022-12-21T18:03:09Z INFO  xdp_hello] Waiting for Ctrl-C...
[2022-12-21T18:03:11Z INFO  xdp_hello] received a packet
[2022-12-21T18:03:11Z INFO  xdp_hello] received a packet
[2022-12-21T18:03:11Z INFO  xdp_hello] received a packet
[2022-12-21T18:03:11Z INFO  xdp_hello] received a packet
^C[2022-12-21T18:03:11Z INFO  xdp_hello] Exiting...
```

So every time a packet was received on the interface, a log was printed!

> [!BUG] Error Loading Program?
> If you get an error loading the program, try changing `XdpFlags::default()`
> to `XdpFlags::SKB_MODE`

### The Lifecycle of an eBPF Program

The program runs until CTRL+C is pressed and then exits.
On exit, Aya takes care of detaching the program for us.

If you issue the `sudo bpftool prog list` command when `xdp_hello` is running
you can verify that it is loaded:

```console
958: xdp  name xdp_hello  tag 0137ce4fce70b467  gpl
    loaded_at 2022-06-23T13:55:28-0400  uid 0
    xlated 2016B  jited 1138B  memlock 4096B  map_ids 275,274,273
    pids xdp-hello(131677)
```

Running the command again once `xdp_hello` has exited will show that the
program is no longer running.

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-hello
[ctrl-c-handler]: https://docs.rs/tokio/latest/tokio/signal/fn.ctrl_c.html
