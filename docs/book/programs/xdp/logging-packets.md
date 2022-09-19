# Logging Packets

In the previous chapter, our XDP application ran until Ctrl-C was hit and permitted all the traffic.
Each time a packet was received, the BPF program created a log entry.
Let's expand this program to log the traffic that is being permitted in the user-space application instead of the BPF program.

!!! example "Source Code"

    Full code for the example in this chapter is availble [here](https://github.com/aya-rs/book/tree/main/examples/myapp-02)

## Getting Data to User-Space

### Sharing Data

To get data from kernel-space to user-space we use an eBPF map. There are numerous types of maps to chose from, but in this example we'll be using a PerfEventArray.

While we could go all out and extract data all the way up to L7, we'll constrain our firewall to L3, and to make things easier, IPv4 only.
The data structure that we'll need to send information to user-space will need to hold an IPv4 address and an action for Permit/Deny, we'll encode both as a `u32`.

```rust linenums="1" title="myapp-common/src/lib.rs"
--8<-- "examples/myapp-02/myapp-common/src/lib.rs"
```

1. We implement the `aya::Pod` trait for our struct since it is Plain Old Data as can be safely converted to a byte-slice and back.

!!! tip "Alignment, padding and verifier errors"

    At program load time, the eBPF verifier checks that all the memory used is
    properly initialized. This can be a problem if - to ensure alignment - the
    compiler inserts padding bytes between fields in your types.

    **Example:**

    ```rust
    #[repr(C)]
    struct SourceInfo {
        source_port: u16,
        source_ip: u32,
    }

    let port = ...;
    let ip = ...;
    let si = SourceInfo { source_port: port, source_ip: ip };
    ```

    In the example above, the compiler will insert two extra bytes between the
    struct fields `source_port` and `source_ip` to make sure that `source_ip` is
    correctly aligned to a 4 bytes address (assuming `mem::align_of::<u32>() ==
    4`).  Since padding bytes are typically not initialized by the compiler,
    this will result in the infamous `invalid indirect read from stack` verifier
    error.

    To avoid the error, you can either manually ensure that all the fields in
    your types are correctly aligned (eg by explicitly adding padding or by
    making field types larger to enforce alignment) or use `#[repr(packed)]`.
    Since the latter comes with its own footguns and can perform less
    efficiently, explicitly adding padding or tweaking alignment is recommended.

    **Solution ensuring alignment using larger types:**

    ```rust
    #[repr(C)]
    struct SourceInfo {
        source_port: u32,
        source_ip: u32,
    }

    let port = ...;
    let ip = ...;
    let si = SourceInfo { source_port: port, source_ip: ip };
    ```

    **Solution with explicit padding:**

    ```rust
    #[repr(C)]
    struct SourceInfo {
        source_port: u16,
        padding: u16,
        source_ip: u32,
    }

    let port = ...;
    let ip = ...;
    let si = SourceInfo { source_port: port, padding: 0, source_ip: ip };
    ```

## Writing Data

### Generating Bindings To vmlinux.h

To get useful data to add to our maps, we first need some useful data structures to populate with data from the `XdpContext`.
We want to log the Source IP Address of incoming traffic, so we'll need to:

1. Read the Ethernet Header to determine if this is an IPv4 Packet
1. Read the Source IP Address from the IPv4 Header

The two structs in the kernel for this are `ethhdr` from `uapi/linux/if_ether.h` and `iphdr` from `uapi/linux/ip.h`.
If I were to use bindgen to generate Rust bindings for those headers, I'd be tied to the kernel version of the system that I'm developing on.
This is where `aya-tool` comes in to play. It can easily generate bindings for using the BTF information in `/sys/kernel/btf/vmlinux`.

First, we must make sure that `bindgen` is installed.
```sh
cargo install bindgen
```

Once the bindings are generated and checked in to our repository they shouldn't need to be regenerated again unless we need to add a new struct.

Lets use `xtask` to automate this so we can easily reproduce this file in future.

We'll add the following code

=== "xtask/src/codegen.rs"

    ```rust linenums="1"
    --8<-- "examples/myapp-02/xtask/src/codegen.rs"
    ```

=== "xtask/Cargo.toml"

    ```toml linenums="1"
    --8<-- "examples/myapp-02/xtask/Cargo.toml"
    ```

=== "xtask/src/main.rs"

    ```rust linenums="1"
    --8<-- "examples/myapp-02/xtask/src/main.rs"
    ```

Once we've generated our file using `cargo xtask codegen` from the root of the project.
We can access these by including `mod bindings` from our eBPF code.

### Getting Packet Data From The Context And Into the Map

The `XdpContext` contains two fields, `data` and `data_end`.
`data` is a pointer to the start of the data in kernel memory and `data_end`, a pointer to the end of the data in kernel memory. In order to access this data and ensure that the eBPF verifier is happy, we'll introduce a helper function called `ptr_at`. This function will ensure that before we access any data, we check that it's contained between `data` and `data_end`. It is marked as `unsafe` because when calling the function, you must ensure that there is a valid `T` at that location or there will be undefined behaviour.

With our helper function in place, we can:

1. Read the Ethertype field to check if we have an IPv4 packet.
1. Read the IPv4 Source Address from the IP header

To do this efficiently we'll add a dependency on `memoffset = "0.6"` in our `myapp-ebpf/Cargo.toml`

!!! tip "Reading Fields Using `offset_of!`"

    As there is limited stack space, it's more memory efficient to use the `offset_of!` macro to read
    a single field from a struct, rather than reading the whole struct and accessing the field by name.

Once we have our IPv4 source address, we can create a `PacketLog` struct and output this to our `PerfEventArray`

The resulting code looks like this:

```rust linenums="1" title="myapp-ebpf/src/main.rs"
--8<-- "examples/myapp-02/myapp-ebpf/src/main.rs"
```

1. Create our map
2. Here's `ptr_at`, which gives ensures packet access is bounds checked
3. Using `ptr_at` to read our ethernet header
4. Outputting the event to the `PerfEventArray`

Don't forget to rebuild your eBPF program!

## Reading Data

In order to read from the `AsyncPerfEventArray`, we have to call `AsyncPerfEventArray::open()` for each online CPU, then we have to poll the file descriptor for events.
While this is do-able using `PerfEventArray` and `mio` or `epoll`, the code is much less easy to follow. Instead, we'll use `tokio`, which was added to our template for us.

We'll need to add a dependency on `bytes = "1"` to `myapp/Cargo.toml` since this will make it easier
to deal with the chunks of bytes yielded by the `AsyncPerfEventArray`.

Here's the code:

```rust linenums="1" title="myapp/src/main.rs"
--8<-- "examples/myapp-02/myapp/src/main.rs"
```

1. Name was not defined in `myapp-ebpf/src/main.rs`, so use `xdp` instead of `myapp`
2. Define our map
3. Call `open()` for each online CPU
4. Spawn a `tokio::task`
5. Create buffers
6. Read events in to buffers
7. Use `read_unaligned` to read our data into a `PacketLog`.
8. Log the event to the console.

## Running the program

As before, the interface can be overwritten by providing the interface name as a parameter, for example, `cargo xtask run -- iface wlp2s0`.

```console
$ cargo xtask run
LOG: SRC 192.168.1.205, ACTION 2
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 140.82.121.6, ACTION 2
```
