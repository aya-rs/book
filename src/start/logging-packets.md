# Logging Packets

In the previous chapter, our XDP application ran until Ctrl-C was hit and permitted all the traffic.
There was however no output on the console, so you just have to trust that it was working correctly. Let's expand this program to log the traffic that is being permitted.


## Getting Data to User-Space

### Sharing Data

To get data from kernel-space to user-space we use an eBPF map. There are numerous types of maps to chose from, but in this example we'll be using a PerfEventArray.

While we could go all out and extract data all the way up to L7, we'll constrain our firewall to L3, and to make things easier, IPv4 only.
The data structure that we'll need to send information to user-space will need to hold an IPv4 address and an action for Permit/Deny, we'll encode both as a `u32`.

Let's go ahead and add that to `myapp-common/src/lib.rs`

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-common/src/lib.rs:struct}}
```

> 💡 **HINT: Struct Alignment**
>
> Structs must be aligned to 8 byte boundaries. You can do this manually, or alternatively you may use `#[repr(packed)]`. If you do not do this, the eBPF verifier will get upset and emit an `invalid indirect read from stack` error.

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-common/src/lib.rs:pod}}
```

We implement the `aya::Pod` trait for our struct since it is Plain Old Data as can be safely converted to a byte-slice and back.

### eBPF: Map Creation

Let's create a map called `EVENTS` in `myapp-ebpf/src/main.rs`

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-ebpf/src/main.rs:map}}
```

When the eBPF program is loaded by Aya, the map will be created for us.

### Userspace: Map Creation

After our call to `probe.attach()` we'll add the following code:


```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp/src/main.rs:map}}
```

Our `perf_array` is a mutable reference to the map that was created after the XDP program was loaded by Aya.

## Writing Data

Now we've got our maps set up, let's add some data!

### Generating Bindings To vmlinux.h

To get useful data to add to our maps, we first need some useful data structures to populate with data from the `XdpContext`.
We want to log the Source IP Address of incoming traffic, so we'll need to:

1. Read the Ethernet Header to determine if this is an IPv4 Packet
1. Read the Source IP Address from the IPv4 Header

The two structs in the kernel for this are `ethhdr` from `uapi/linux/if_ether.h` and `iphdr` from `uapi/linux/ip.h`.
If I were to use bindgen to generate Rust bindings for those headers, I'd be tied to the kernel version of the system that I'm developing on.
This is where `aya-gen` comes in to play. It can easily generate bindings for using the BTF information in `/sys/kernel/btf/vmlinux`.

Once the bindings are generated and checked in to our repository they shouldn't need to be regenerated again unless we need to add a new struct.

Lets use `xtask` to automate this so we can easily reproduce this file in future.

We'll add the following content to `xtask/src/codegen.rs`

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/xtask/src/codegen.rs}}
```

This will generate a file called `myapp-ebpf/src/bindings.rs`. If you've chosen an application name other than `myapp` you'll need to adjust the path appropriately.

Add a new dependencies to `xtask/Cargo.toml`:

```toml
[dependencies]
aya-gen = { git = "http://github.com/aya-rs/aya", branch = "main" }
```

Finally, we must add the command to the enum in `xtask/src/main.rs`:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/xtask/src/main.rs:enum}}
```

And then add the new variant to the `match` statement:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/xtask/src/main.rs:subcommand}}
```


Once we've generated our file using `cargo xtask codegen` from the root of the project.

These can then be accessed from within `myapp-ebpf/src/main.rs`:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-ebpf/src/main.rs:bindings}}
```

### Getting Packet Data From The Context

The `XdpContext` contains two fields, `data` and `data_end`.
`data` is a pointer to the start of the data in kernel memory and `data_end`, a pointer to the end of the data in kernel memory. In order to access this data and ensure that the eBPF verifier is happy, we'll introduce a helper function:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-ebpf/src/main.rs:ptr_at}}
```

This function will ensure that before we access any data, we check that it's contained between `data` and `data_end`.
It is marked as `unsafe` because when calling the function, you must ensure that there is a valid `T` at that location or there will be undefined behaviour.

### Writing Data To The Map

With our helper function in place, we can:
1. Read the Ethertype field to check if we have an IPv4 packet.
1. Read the IPv4 Source Address from the IP header

First let's add another dependency on `memoffset = "0.6"` to `myapp-ebpf/Cargo.toml`, and then we'll change our `try_xdp_firewall` function to look like this:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp-ebpf/src/main.rs:try}}
```

> 💡 **HINT: Reading Fields Using `offset_of!`**
>
> As there is limited stack space, it's more memory efficient to use the `offset_of!` macro to read
> a single field from a struct, rather than reading the whole struct and accessing the field by name.

Once we have our IPv4 source address, we can create a `PacketLog` struct and output this to our PerfEventArray

## Reading Data

### Going Async

In order to read from the `AsyncPerfEventArray`, we have to call `AsyncPerfEventArray::open()` for each online CPU, then we have to poll the file descriptor for events.
While this is do-able using `PerfEventArray` and `mio` or `epoll`, the code is much less easy to follow. Instead, we'll use `tokio` to make our user-space application async.


Let's add some dependencies to `myapp/src/Cargo.toml`:

```toml
{{#include ../../examples/myapp-02/myapp/Cargo.toml:7:12}}
```

And adjust our `main` function in `myapp/src/main.rs` to look like this:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp/src/main.rs:main}}
```

This will now spawn a `tokio::task` to read each of the `AsyncPerfEventArrayBuffers` contained in out `AsyncPerfEventArray`.
When we receive an event, we use `read_unaligned` to read our data into a `PacketLog`.
We then use `println!` to log the event to the console.
We no longer need to sleep, as we run until we receive the `CTRL+C` signal.

## Running the program

```console
cargo build
cargo xtask build-ebpf
sudo ./target/debug/myapp ./target/bpfel-unknown-none/debug/myapp wlp2s0
```

```console
LOG: SRC 192.168.1.205, ACTION 2
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 140.82.121.6, ACTION 2
```
