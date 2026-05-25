# Sockets

> [!NOTE]
> Full code for the example in this chapter is available [on GitHub][source-code].

[eBPF program type description][sock-ops-docs]

## Example project

You can follow the
[basic XDP example](../start/development.md#starting-a-new-project)
to make a project structure.

E.g.: `cargo generate --name hello-sockops -d program_type=sock_ops https://github.com/aya-rs/aya-template`

## eBPF code

This example logs IPv4 socket information from a SockOps program.
The program:

- Checks whether the socket family is `AF_INET`,
- Reads the local address, local port, and current pid from `SockOpsContext`,
- Logs the operation and returns `1` to indicate success.

Here's how the eBPF code looks like:

```rust,ignore
{{#include ../../../examples/hello-sockops/hello-sockops-ebpf/src/main.rs}}
```

## Userspace code

The userspace side loads the compiled eBPF object, initializes Aya's logger,
loads the `socket_ops` program, and attaches it to the root cgroup.

Here's how the code looks like:

```rust,ignore
{{#include ../../../examples/hello-sockops/hello-sockops/src/main.rs}}
```

Try to start the program with `RUST_LOG=warn cargo run` and run `curl goo.gle`
in another terminal to see information on the new socket logged
by the eBPF program.

[sock-ops-docs]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS
[source-code]: https://github.com/aya-rs/book/tree/main/examples/hello-sockops
