# Getting data to user-space

In previous chapters we were logging packets with aya-log. However, what if we
need to send additional data about the packet or any other type of information
for the user-space program to utilize? In this chapter, we will explore how to
leverage perf buffers and define data structures in the *-common* crate to
transfer data from eBPF program to user-space applications. By doing so,
user-space programs can access and utilize the transferred data effectively.

!!! example "Source code"

    Full code for the example in this chapter is available
    [here](https://github.com/aya-rs/book/tree/main/examples/xdp-perfbuf-custom-data)

## Sharing data

In this chapter, we will be sending data from the kernel space to the user space
by writing it into a struct and outputting it to user space. We can achieve this
by using an eBPF map. There are different types of maps available, but in this
case, we will use `PerfEventArray`.

`PerfEventArray` is a collection of per-CPU circular buffers that enable the
kernel to emit events (defined as custom structs) to user space. Each CPU has
its own buffer, and the eBPF program emits an event to the buffer of the CPU
it's currently running on. The events are unordered, meaning that they arrive
in the user-space in a different order than they were created and sent from the
eBPF program.

To gather events from all CPUs, we are going to spawn a task for each CPU to
poll for the events and then iterate over them.

The data structure we'll be using needs to hold an IPv4 address and a port.

```rust linenums="1" title="xdp-perfbuf-custom-data-common/src/lib.rs"
--8<-- "examples/xdp-perfbuf-custom-data/xdp-perfbuf-custom-data-common/src/lib.rs"
```

1. We implement the `aya::Pod` trait for our struct since it is Plain Old Data
as can be safely converted to a byte slice and back.

1. Events emitted with `PerfEventArray` are copied from kernel memory to user
memory, therefore they must implement the `aya::Pod` trait (where `Pod` stands
for "plain old data") which expresses that it's safe to convert them into a
sequence of bytes.

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

    let source_port = ...;
    let source_ip = ...;
    let si = SourceInfo { source_port, source_ip };
    ```

    In the example above, the compiler will insert two extra bytes between the
    struct fields `source_port` and `source_ip` to make sure that `source_ip` is
    correctly aligned to a 4-byte address (assuming `mem::align_of::<u32>() ==
    4`).  Since padding bytes are typically not initialized by the compiler,
    this will result in the infamous `invalid indirect read from stack` verifier
    error.

    To avoid the error, you can either manually ensure that all the fields in
    your types are correctly aligned (e.g. by explicitly adding padding or by
    making field types larger to enforce alignment) or use `#[repr(packed)]`.
    Since the latter comes with its own foot-guns and can perform less
    efficiently, explicitly adding padding or tweaking alignment is recommended.

    **Solution ensuring alignment using larger types:**

    ```rust
    #[repr(C)]
    pub struct SourceInfo {
        pub source_port: u32,
        pub source_ip: u32,
    }

    let source_port = ...;
    let source_ip = ...;
    let si = SourceInfo { source_port, source_ip };
    ```

    **Solution with explicit padding:**

    ```rust
    #[repr(C)]
    pub struct SourceInfo {
        pub source_port: u16,
        _padding: u16,
        pub source_ip: u32,
    }

    let source_port = ...;
    let source_ip = ...;
    let si = SourceInfo { source_port, padding: 0, source_ip };
    ```

## Extracting packet data from the context and into the map

The eBPF program code in this section is similar to the one in the previous
chapters. It extracts the source IP address and port information from packet
headers.

The difference is that after obtaining the data from the headers, we create a
`PacketLog` struct and output it to our `PerfEventArray` instead of logging data
directly.

The resulting code looks like this:

```rust linenums="1" title="xdp-perfbuf-custom-data-ebpf/src/main.rs"
--8<-- "examples/xdp-perfbuf-custom-data/xdp-perfbuf-custom-data-ebpf/src/main.rs"
```

1. Create our map.
2. Output the event to the map.

## Reading data

To read from the perf event array in user space, we need to choose one of the
following types:

* `AsyncPerfEventArray` which is designed for use with
  [async Rust](https://rust-lang.github.io/async-book/01_getting_started/01_chapter.html).
* `PerfEventArray`, intended for synchronous Rust.

By default, [our project template](https://github.com/aya-rs/aya-template) is
written in async Rust and uses the [Tokio runtime](https://tokio.rs/). Therefore,
we will use `AsyncPerfEventArray` in this chapter.

To read from the `AsyncPerfEventArray`, we must call
`AsyncPerfEventArray::open()` for each online CPU and poll the file descriptor
for events.

Additionally, we need to add a dependency on `bytes` to `xdp-log/Cargo.toml`.
This library simplifies handling the chunks of bytes yielded by the
`AsyncPerfEventArray`.

Here's the code:

```rust linenums="1" title="xdp-perfbuf-custom-data/src/main.rs"
--8<-- "examples/xdp-perfbuf-custom-data/xdp-perfbuf-custom-data/src/main.rs"
```

1. Define our map.
2. Call `open()` for each online CPU.
3. Spawn a `tokio::task`.
4. Create buffers.
5. Read events in to buffers.
6. Use `read_unaligned` to read the event data into a `PacketLog`.
7. Log the packet data.

## Running the program

As before, you can overwrite the interface by by providing the interface name as
a parameter, for example, `RUST_LOG=info cargo xtask run -- --iface wlp2s0`.

```console
$ RUST_LOG=info cargo xtask run
[2023-01-25T08:57:41Z INFO  xdp_perfbuf_custom_data] SRC IP: 60.235.240.157, SRC_PORT: 443
[2023-01-25T08:57:41Z INFO  xdp_perfbuf_custom_data] SRC IP: 98.21.76.76, SRC_PORT: 443
[2023-01-25T08:57:41Z INFO  xdp_perfbuf_custom_data] SRC IP: 95.194.217.172, SRC_PORT: 443
[2023-01-25T08:57:41Z INFO  xdp_perfbuf_custom_data] SRC IP: 95.194.217.172, SRC_PORT: 443
[2023-01-25T08:57:41Z INFO  xdp_perfbuf_custom_data] SRC IP: 95.10.251.142, SRC_PORT: 443
```
