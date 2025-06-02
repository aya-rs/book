# Dropping Packets

In the previous chapter our XDP program just logged traffic. In this chapter
we're going to extend it to allow the dropping of traffic.

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [on GitHub][source-code].

## Design

In order for our program to drop packets, we're going to need a list of IP
addresses to drop. Since we want to be able to lookup them up efficiently, we're
going to use a
[`HashMap`](https://docs.rs/aya/latest/aya/maps/struct.HashMap.html) to hold
them.

We're going to:

- Create a `HashMap` in our eBPF program that will act as a blocklist
- Check the IP address from the packet against the `HashMap` to make a policy
  decision (pass or drop)
- Add entries to the blocklist from userspace

## Dropping packets in eBPF

We will create a new map called `BLOCKLIST` in our eBPF code. In order to make
the policy decision, we will need to lookup the source IP address in our
`HashMap`. If it exists we drop the packet, if it does not, we allow it. We'll
keep this logic in a function called `block_ip`.

Here's what the code looks like now:

```rust linenums="1" title="xdp-drop-ebpf/src/main.rs"
--8<-- "examples/xdp-drop/xdp-drop-ebpf/src/main.rs"
```

1. Create our map
1. Check if we should allow or deny our packet
1. Return the correct action

## Populating our map from userspace

In order to add the addresses to block, we first need to get a reference to the
`BLOCKLIST` map. Once we have it, it's simply a case of calling
`blocklist.insert()`. We'll use the `IPv4Addr` type to represent our IP address
as it's human-readable and can be easily converted to a `u32`. We'll block all
traffic originating from `1.1.1.1` in this example.

> [!NOTE] Endianness
> IP addresses are always encoded in network byte order (big endian) within
> packets. In our eBPF program, before checking the blocklist, we convert them
> to host endian using `u32::from_be_bytes`. Therefore it's correct to write
> our IP addresses in host endian format from userspace.
>
> The other approach would work too: we could convert IPs to network endian
> when inserting from userspace, and then we wouldn't need to convert when
> indexing from the eBPF program.

Here's how the userspace code looks:

```rust linenums="1" title="xdp-drop/src/main.rs"
--8<-- "examples/xdp-drop/xdp-drop/src/main.rs"
```

1. Get a reference to the map
1. Create an IPv4Addr
1. Write this to our map

## Running the program

```console
$ RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 1.1.1.1, ACTION: 1
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 192.168.1.21, ACTION: 2
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 192.168.1.21, ACTION: 2
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 18.168.253.132, ACTION: 2
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 1.1.1.1, ACTION: 1
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 18.168.253.132, ACTION: 2
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 18.168.253.132, ACTION: 2
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 1.1.1.1, ACTION: 1
[2022-10-04T12:46:05Z INFO  xdp_drop] SRC: 140.82.121.6, ACTION: 2
```

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-drop
