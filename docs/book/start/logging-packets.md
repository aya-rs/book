# Logging Packets

In the previous chapter, our XDP application ran until Ctrl-C was hit and permitted all the traffic.
Each time a packet was received, the BPF program created a log entry.
Let's expand this program to log the traffic that is being permitted in the user-space application instead of the BPF program.

!!! example "Source Code"

    Full code for the example in this chapter is available [here](https://github.com/aya-rs/book/tree/main/examples/xdp-log)

## Getting Data to User-Space

### Sharing Data

To get data from kernel-space to user-space we use an eBPF map. There are numerous types of maps to chose from, but in this example we'll be using a PerfEventArray.

While we could go all out and extract data all the way up to L7, we'll constrain our firewall to L3, and to make things easier, IPv4 only.
The data structure that we'll need to send information to user-space will need to hold an IPv4 address and an action for Permit/Deny, we'll encode both as a `u32`.

```rust linenums="1" title="xdp-log-common/src/lib.rs"
--8<-- "examples/xdp-log/xdp-log-common/src/lib.rs"
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

### Using Kernel Network Types

To get useful data to add to our maps, we first need some useful data structures
to populate with data from the `XdpContext`.
We want to log the Source IP Address of incoming traffic, so we'll need to:

1. Read the Ethernet Header to determine if this is an IPv4 Packet
1. Read the Source IP Address from the IPv4 Header

The two structs in the kernel for this are `ethhdr` from `uapi/linux/if_ether.h`
and `iphdr` from `uapi/linux/ip.h`. Rust equivalents of those structures (`EthHdr`
and `Ipv4Hdr`) are provided by the [network-types crate](https://crates.io/crates/network-types).

Let's add it to our eBPF crate by adding a dependency on `network-types` in our
`xdp-log-ebpf/Cargo.toml`:

=== "xdp-log-ebpf/Cargo.toml"

    ```toml linenums="1"
    --8<-- "examples/xdp-log/xdp-log-ebpf/Cargo.toml"
    ```

### Getting Packet Data From The Context And Into the Map

The `XdpContext` contains two fields, `data` and `data_end`.
`data` is a pointer to the start of the data in kernel memory and `data_end`, a
pointer to the end of the data in kernel memory. In order to access this data
and ensure that the eBPF verifier is happy, we'll introduce a helper function
called `ptr_at`. This function will ensure that before we access any data, we
check that it's contained between `data` and `data_end`. It is marked as `unsafe`
because when calling the function, you must ensure that there is a valid `T` at
that location or there will be undefined behaviour.

With our helper function in place, we can:

1. Read the Ethertype field to check if we have an IPv4 packet.
1. Read the IPv4 Source Address from the IP header

Once we have our IPv4 source address, we can create a `PacketLog` struct and output this to our `PerfEventArray`

The resulting code looks like this:

```rust linenums="1" title="xdp-log-ebpf/src/main.rs"
--8<-- "examples/xdp-log/xdp-log-ebpf/src/main.rs"
```

1. Create our map
2. Here's `ptr_at`, which gives ensures packet access is bounds checked
3. Using `ptr_at` to read our ethernet header
4. Outputting the event to the `PerfEventArray`

Don't forget to rebuild your eBPF program!

## Reading Data

In order to read from the `AsyncPerfEventArray`, we have to call `AsyncPerfEventArray::open()` for each online CPU, then we have to poll the file descriptor for events.
While this is do-able using `PerfEventArray` and `mio` or `epoll`, the code is much less easy to follow. Instead, we'll use `tokio`, which was added to our template for us.

We'll need to add a dependency on `bytes = "1"` to `xdp-log/Cargo.toml` since this will make it easier
to deal with the chunks of bytes yielded by the `AsyncPerfEventArray`.

Here's the code:

```rust linenums="1" title="xdp-log/src/main.rs"
--8<-- "examples/xdp-log/xdp-log/src/main.rs"
```

1. Name was not defined in `xdp-log-ebpf/src/main.rs`, so use `xdp`
2. Define our map
3. Call `open()` for each online CPU
4. Spawn a `tokio::task`
5. Create buffers
6. Read events in to buffers
7. Use `read_unaligned` to read our data into a `PacketLog`.
8. Log the event to the console.

## Running the program

As before, the interface can be overwritten by providing the interface name as a parameter, for example, `RUST_LOG=info cargo xtask run -- --iface wlp2s0`.

```console
$ RUST_LOG=info cargo xtask run
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 234.130.159.162, SRC PORT: 443
```
