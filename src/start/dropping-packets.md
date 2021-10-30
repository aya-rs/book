# Dropping Packets

In the previous chapter, our XDP logged traffic. In this chapter we're going to extend it
to allow the dropping of traffic


## Design

In order for our program to drop packets, we're going to need a list of IP Addresses to drop.
Seeing as we want to do quick lookups a HashMap would be a good datastructure.
Therefore:

- We need to create a HashMap in our BPF Program
- Check the destination IP Address from the packet against the HashMap to make a forwarding decision
- Add entries to the blocklist from userspace

### eBPF: Map Creation

Let's create a new map called `BLOCKLIST` in `myapp-ebpf/src/main.rs`

```rust,ignore
{{#rustdoc_include ../../examples/myapp-03/myapp-ebpf/src/main.rs:blocklist}}
```

### eBPF: Forwarding Decision

In order to make our forwarding decision, we first need to read from the HashMap.
We'll implement a function called `block_ip` which will return `true` if the IP should be blocked and `false` if it should pass.

```rust,ignore
{{#rustdoc_include ../../examples/myapp-03/myapp-ebpf/src/main.rs:block_ip}}
```

We'll then call `block_ip` to determine the fate of the packet:

```rust,ignore
{{#rustdoc_include ../../examples/myapp-03/myapp-ebpf/src/main.rs:action}}
```

### Userspace: Adding IP Addresses to Block

In order to add addresses to block, we first need to get a reference to the `BLOCKLIST` map.
Once we have it, it's simply a case of calling `blocklist.insert()`.
We'll use the `IPv4Addr` type to represent our IP address as it's human-readable and can be easily converted to a `u32`. We'll block all traffic **to** `192.168.0.10` sent over the `lo` interface, for this example.

```rust,ignore
{{#rustdoc_include ../../examples/myapp-02/myapp/src/main.rs:block_address}}
```

> 💡 **HINT: A quick note on Endianness**
>
> IP Addresses are always NetworkEndian (BigEndian). However, in our eBPF Program we convert
> it to HostEndian format using `u32::from_be`. Therefore it's correct to write our IP Addresses
> in host-endian format when used as Map Keys.
> If you had not converted it in your eBPF Program then you would need to convert it to
> BigEndian format for use as a key.


## Running the program

```console
cargo build
cargo xtask build-ebpf
sudo ./target/debug/myapp --path ./target/bpfel-unknown-none/debug/myapp --intf lo
```

### Testing the Allowed IP addresses

```console
curl --interface lo 192.168.0.22
```

```console
LOG: SRC 192.168.0.22, ACTION 2
LOG: SRC 192.168.0.22, ACTION 2
```

### Testing the Blocked IP address
```console
curl --interface lo 192.168.0.10
```

```console
LOG: SRC 192.168.0.10, ACTION 1
LOG: SRC 192.168.0.10, ACTION 1
```
