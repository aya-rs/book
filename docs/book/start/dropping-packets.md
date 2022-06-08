# Dropping Packets

In the previous chapter, our XDP logged traffic. In this chapter we're going to extend it
to allow the dropping of traffic

!!! example "Source Code"

    Full code for the example in this chapter is availble [here](https://github.com/aya-rs/book/tree/main/examples/myapp-03)

## Design

In order for our program to drop packets, we're going to need a list of IP Addresses to drop.
Seeing as we want to do quick lookups a HashMap would be a good datastructure.
Therefore:

- We need to create a HashMap in our BPF Program
- Check the IP Address from the packet against the HashMap to make a forwarding decision
- Add entries to the blocklist from userspace

## Dropping packets in eBPF

We will create a new map called `BLOCKLIST` in our eBPF code.
In order to make our forwarding decision, we will need to lookup the destination IP address in our HashMap.
If it exists, we drop the packet, if it does not, we allow it.
We'll keep this logic in a function called `block_ip`.

Here's what the code looks like now:

```rust linenums="1" title="myapp-ebpf/src/main.rs"
--8<-- "examples/myapp-03/myapp-ebpf/src/main.rs"
```

1. Create our map
2. Check if we should allow or deny our packet
3. Return the correct action

## Populating our map from userspace

In order to add addresses to block, we first need to get a reference to the `BLOCKLIST` map.
Once we have it, it's simply a case of calling `blocklist.insert()`.
We'll use the `IPv4Addr` type to represent our IP address as it's human-readable and can be easily converted to a `u32`. We'll block all traffic to `1.1.1.1` for this example.

!!! note "Endianness"

    IP Addresses are always NetworkEndian (BigEndian). However, in our eBPF Program we convert
    it to HostEndian format using `u32::from_be`. Therefore it's correct to write our IP Addresses
    in host-endian format when used as Map Keys.
    If you had not converted it in your eBPF Program then you would need to convert it to
    BigEndian format for use as a key.

Here's how the userspace code looks:

```rust linenums="1" title="myapp/src/main.rs"
--8<-- "examples/myapp-03/myapp/src/main.rs"
```

1. Get a reference to the map
2. Create an IPv4Addr
3. Write this to our map
## Running the program

```console
$ cargo xtask run
LOG: SRC 192.168.1.205, ACTION 2
LOG: SRC 1.1.1.1, ACTION 1
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 192.168.1.21, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 1.1.1.1, ACTION 1
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 18.168.253.132, ACTION 2
LOG: SRC 1.1.1.1, ACTION 1
LOG: SRC 140.82.121.6, ACTION 2
```
