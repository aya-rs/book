# Probes

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [on GitHub][source-code].

## What are the probes in eBPF?

The probe BPF programs attach to kernel (kprobes) or user-side (uprobes)
functions and are able to access the function parameters of those functions.
You can find more information about probes in the
[kernel documentation][kernel-docs], including the difference between kprobes
and kretprobes.

## Example project

To illustrate kprobes with Aya, let's write a program which
attaches a eBPF handler to the [`tcp_connect`][tcp-connect] function and allows
printing the source and destination IP addresses from the socket parameter.

## Design

For this demo program, we are going to rely on aya-log to print IP addresses
from the BPF program and not going to have any custom BPF maps (besides those
created by aya-log).

## eBPF code

- From the `tcp_connect` signature, we see that `struct sock *sk` is the only
  function parameter. We will access it from the `ProbeContext` ctx handle.
- We call `bpf_probe_read_kernel` helper to copy the
  `struct sock_common __sk_common` portion of the socket structure. (For uprobe
  programs, we would need to call `bpf_probe_read_user` instead.)
- We match the `skc_family` field, and for `AF_INET` (IPv4) and `AF_INET6`
  (IPv6) values, extract and print the src and destination addresses using
  aya-log `info!` macro.

Here's how the eBPF code looks like:

```rust linenums="1" title="kprobetcp-ebpf/src/main.rs"
--8<-- "examples/kprobetcp/kprobetcp-ebpf/src/main.rs"
```

## Userspace code

The purpose of the userspace code is to load the eBPF program and attach it to the
`tcp_connect` function.

Here's how the code looks like:

```rust linenums="1" title="kprobetcp/src/main.rs"
--8<-- "examples/kprobetcp/kprobetcp/src/main.rs"
```

## Running the program

<!-- markdownlint-disable MD013 -->

```console
$ RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
[2022-12-28T20:50:00Z INFO  kprobetcp] Waiting for Ctrl-C...
[2022-12-28T20:50:05Z INFO  kprobetcp] AF_INET6 src addr: 2001:4998:efeb:282::249, dest addr: 2606:2800:220:1:248:1893:25c8:1946
[2022-12-28T20:50:11Z INFO  kprobetcp] AF_INET src address: 10.53.149.148, dest address: 10.87.116.72
[2022-12-28T20:50:30Z INFO  kprobetcp] AF_INET src address: 10.53.149.148, dest address: 98.138.219.201
```

<!-- markdownlint-enable MD013 -->

[source-code]: https://github.com/aya-rs/book/tree/main/examples/kprobetcp
[kernel-docs]: https://docs.kernel.org/trace/kprobes.html
[tcp-connect]: https://elixir.bootlin.com/linux/latest/source/net/ipv4/tcp_output.c#L3837
