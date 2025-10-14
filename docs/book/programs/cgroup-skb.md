# Cgroup SKB

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [on GitHub][source-code].

## What is Cgroup SKB?

Cgroup SKB programs are attached to v2 cgroups and get triggered by network
traffic (egress or ingress) associated with processes inside the given cgroup.
They allow to intercept and filter the traffic associated with particular
cgroups (and therefore - containers).

## What's the difference between Cgroup SKB and Classifiers?

Both Cgroup SKB and Classifiers receive the same type of context -
`SkBuffContext`.

The difference is that Classifiers are attached to the network interface.

## Example project

This example will be similar to the [Classifier](classifiers.md) example - a
program which allows the dropping of egress traffic, but for the specific
cgroup.

## Design

We're going to:

- Create a `HashMap` that will act as a blocklist.
- Check the destination IP address from the packet against the `HashMap` to
  make a policy decision (pass or drop).
- Add entries to the blocklist from userspace.

## Using network types

In this example, we are going to read the IPv4 protocol header. We need to use
the [network-types][network-types] crate that provides it, as well as many
other type definitions of the common Internet protocols.

Let's add it to `cgroup-skb-egress-ebpf/Cargo.toml`:

```toml linenums="1" title="cgroup-skb-egress-ebpf/Cargo.toml"
--8<-- "examples/cgroup-skb-egress/cgroup-skb-egress-ebpf/Cargo.toml"
```

## eBPF code

The program is going to start with a definition of `BLOCKLIST` map. To enforce
the police, the program is going to lookup the destination IP address in that
map. If the map entry for that address exists, we are going to drop the packet
by returning `0`. Otherwise, we are going to accept it by returning `1`.

Here's how the eBPF code looks like:

```rust linenums="1" title="cgroup-skb-egress-ebpf/src/main.rs"
--8<-- "examples/cgroup-skb-egress/cgroup-skb-egress-ebpf/src/main.rs"
```

1. Create our map.
1. Check if we should allow or deny our packet.
1. Return the correct action.

## Userspace code

The purpose of the userspace code is to load the eBPF program, attach it to the
cgroup and then populate the map with an address to block.

In this example, we'll block all egress traffic going to `1.1.1.1`.

Here's how the code looks like:

```rust linenums="1" title="cgroup-skb-egress/src/main.rs"
--8<-- "examples/cgroup-skb-egress/cgroup-skb-egress/src/main.rs"
```

1. Loading the eBPF program.
1. Attaching it to the given cgroup.
1. Populating the map with remote IP addresses which we want to prevent the
   egress traffic to.

The third thing is done with getting a reference to the `BLOCKLIST` map and
calling `blocklist.insert`. Using `IPv4Addr` type in Rust will let us to read
the human-readable representation of IP address and convert it to `u32`, which
is an appropriate type to use in eBPF maps.

## Testing the program

First, check where cgroups v2 are mounted:

```console
$ mount | grep cgroup2
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
```

The most common locations are either `/sys/fs/cgroup` or `/sys/fs/cgroup/unified`.

Inside that location, we need to create our new cgroup (as root):

```console
mkdir /sys/fs/cgroup/foo
```

Then run the program with:

```console
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

And then, in a separate terminal, as root, try to access `1.1.1.1`:

```console
bash -c "echo \$$ >> /sys/fs/cgroup/foo/cgroup.procs && curl 1.1.1.1"
```

That command should hang and the logs of our program should look like:

```console
LOG: DST 1.1.1.1, ACTION 0
LOG: DST 1.1.1.1, ACTION 0
```

On the other hand, accessing any other address should be successful, for
example:

```console
$ bash -c "echo \$$ >> /sys/fs/cgroup/foo/cgroup.procs && curl google.com"
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
```

And should result in the following logs:

```console
LOG: DST 192.168.88.10, ACTION 1
LOG: DST 192.168.88.10, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
LOG: DST 172.217.19.78, ACTION 1
```

[source-code]: https://github.com/aya-rs/book/tree/main/examples/cgroup-skb-egress
[network-types]: https://crates.io/crates/network-types
