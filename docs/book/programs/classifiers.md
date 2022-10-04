# Classifiers

!!! example "Source Code"

    Full code for the example in this chapter is available [here](https://github.com/aya-rs/book/tree/main/examples/tc-egress)

## What is Classifier in eBPF?

Classifier is a type of eBPF program which is attached to **queuing disciplines**
in Linux kernel networking (often referred to as **qdisc**) and therefore being
able to make decisions about packets that have been received on the network
interface associated with the qdisc.

For each network interface, there are separate qdiscs for ingress and egress
traffic. When attaching Classifier program to an interface,

## What's the difference between Classifiers and XDP?

* Classifier is older than XDP, it's available since kernel 4.1, while XDP -
  since 4.8.
* Classifier can inspect both ingress and egress traffic. XDP is limited to
  ingress.
* XDP provides better performance, because it's executed earlier - it receives
  a raw packet from the NIC driver, before it goes to any layers of kernel
  networking stack and gets parsed to the `sk_buff` structure.

## Example project

To make a difference from the XDP example, let's try to write a program which
allows the dropping of egress traffic.

## Design

We're going to:

- Create a `HashMap` that will act as a blocklist.
- Check the destination IP address from the packet against the `HashMap` to
  make a policy decision (pass or drop).
- Add entries to the blocklist from userspace.

## eBPF code

The program code is going to start with a definition of `BLOCKLIST` map. To
enforce the policy, the program is going to lookup the destination IP address in
that map. If the map entry for that address exist, we are going to drop the
packet. Otherwise, we are going to **pipe** it with `TC_ACT_PIPE` action - which
means allowing it on our side, but let the packet be inspected also by another
Classifier programs and qdisc filters.

!!! note "TC_ACT_OK"

    There is also a possibility to allow the packet while bypassing the other
    programs and filters - `TC_ACT_OK`. We recommend that option only if absolutely
    sure that you want your program to have a precedence over the other programs
    or filters.

Here's how the eBPF code looks like:

```rust linenums="1" title="tc-egress-ebpf/src/main.rs"
--8<-- "examples/tc-egress/tc-egress-ebpf/src/main.rs"
```

1. Create our map.
2. Check if we should allow or deny our packet.
3. Return the correct action.

## Userspace code

The purpose of the userspace code is to load the eBPF program, attach it to the
given network interface and then populate the map with an address to block.

In this example, we'll block all egress traffic going to `1.1.1.1`.

Here's how the code looks like:

```rust linenums="1" title="tc-egress/src/main.rs"
--8<-- "examples/tc-egress/tc-egress/src/main.rs"
```

1. Loading the eBPF program.
2. Attaching it to the given network interface.
3. Populating the map with remote IP addresses which we want to prevent the
   egress traffic to.

The third thing is done with getting a reference to the `BLOCKLIST` map and
calling `blocklist.insert`. Using `IPv4Addr` type in Rust will let us to read
the human-readable representation of IP address and convert it to `u32`, which
is an appropriate type to use in eBPF maps.

## Running the program

```console
$ RUST_LOG=info cargo xtask run
LOG: SRC 1.1.1.1, ACTION 2
LOG: SRC 35.186.224.47, ACTION 3
LOG: SRC 35.186.224.47, ACTION 3
LOG: SRC 1.1.1.1, ACTION 2
LOG: SRC 168.100.68.32, ACTION 3
LOG: SRC 168.100.68.239, ACTION 3
LOG: SRC 168.100.68.32, ACTION 3
LOG: SRC 168.100.68.239, ACTION 3
LOG: SRC 1.1.1.1, ACTION 2
LOG: SRC 13.248.212.111, ACTION 3
```
