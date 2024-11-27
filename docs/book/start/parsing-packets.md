# Parsing packets

In the previous chapter, our XDP application ran until Ctrl-C was hit and
permitted all the traffic. Each time a packet was received, the eBPF program
logged the string `"received a packet"`. In this chapter we're going to show how
to parse packets.

While we could go all out and parse data all the way up to L7, we'll constrain
our example to L3, and to make things easier, IPv4 only.

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [here][source-code].

## Using network types

We're going to log the source IP address of incoming packets. So we'll need to:

* Read the Ethernet header to determine if we're dealing with an IPv4 packet,
  else terminate parsing.
* Read the source IP Address from the IPv4 header.

We could read the specifications of those protocols and parse manually, but
instead we're going to use the [network-types](https://crates.io/crates/network-types)
crate which provides convenient type definitions for many of the common Internet
protocols.

Let's add it to our eBPF crate by adding a dependency on `network-types` in our
`xdp-log-ebpf/Cargo.toml`:

```toml linenums="1" title="xdp-log-ebpf/Cargo.toml"
--8<-- "examples/xdp-log/xdp-log-ebpf/Cargo.toml"
```

## Getting packet data from the context

`XdpContext` contains two fields that we're going to use: `data` and `data_end`,
which are respectively a pointer to the beginning and to the end of the packet.

In order to access the data in the packet and to ensure that we do so in a way
that keeps the eBPF verifier happy, we're going to introduce a helper function
called `ptr_at`. The function ensures that before we access any packet data, we
insert the bound checks which are required by the verifier.

Finally to access individual fields from the Ethernet and IPv4 headers, we're
going to use the memoffset crate, let's add a dependency for it in
`xdp-log-ebpf/Cargo.toml`.

> [!TIP] Reading fields using `offset_of!`
> As there is limited stack space, it's more memory efficient to use the
> `offset_of!` macro to read a single field from a struct, rather than reading
> the whole struct and accessing the field by name.

The resulting code looks like this:

```rust linenums="1" title="xdp-log-ebpf/src/main.rs"
--8<-- "examples/xdp-log/xdp-log-ebpf/src/main.rs"
```

1. Here we define `ptr_at` to ensure that packet access is always bound checked.
1. Use `ptr_at` to read our ethernet header.
1. Here we log IP and port.

Don't forget to rebuild your eBPF program!

## User-space component

Our user-space code doesn't really differ from the previous chapter, but for the
reference, here's the code:

```rust linenums="1" title="xdp-log/src/main.rs"
--8<-- "examples/xdp-log/xdp-log/src/main.rs"
```

## Running the program

As before, the interface can be overwritten by providing the interface name as a
parameter, for example, `RUST_LOG=info cargo xtask run -- --iface wlp2s0`.

```console
$ RUST_LOG=info cargo xtask run
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 172.52.22.104, SRC PORT: 443
[2022-12-22T11:32:21Z INFO  xdp_log] SRC IP: 234.130.159.162, SRC PORT: 443
```

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-log
