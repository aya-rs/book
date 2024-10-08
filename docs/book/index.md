# Getting Started

This getting started guide will help you use the Rust
Programming Language and Aya library to build extended Berkley Packet Filter (eBPF)
programs.

## Who Aya Is For

Rust is proving to be a popular systems programming language because of its
safety features and excellent C interoperability. The safety features are less
important in the context of eBPF as programs often need to read kernel memory,
which is considered unsafe. However, what Rust combined with Aya does offer is
a fast and efficient development experience:

- Cargo for project scaffolding, build, test and debugging
- Generation of Rust bindings to Kernel Headers with Compile-Once,
  Run-Everywhere (CO-RE) support
- Easy code sharing between user-space and eBPF programs
- Fast compile times
- No runtime dependency on LLVM, BCC or libbpf

## Scope

The goals of this guide are:

- Get developers up to speed with eBPF Rust development. i.e. How to set
  up a development environment.
- Share *current* best practices about using Rust for eBPF

## Who This Guide is For

This guide caters towards people with either some eBPF or some Rust background.
For those without any prior knowledge we suggest you read the "Assumptions and
Prerequisites" section first. You can check out the "Other Resources" section
to find resources on topics you might want to read up on.

### Assumptions and Prerequisites

- You are comfortable using the Rust Programming Language, and have written,
  run, and debugged Rust applications on a desktop environment. You should also
  be familiar with the idioms of the [2021 edition] as this guide targets
  Rust 2021.

[2021 edition]: https://doc.rust-lang.org/edition-guide/

- You are familiar with the core concepts of eBPF

### Other Resources

If you are unfamiliar with anything mentioned above or if you want more
information about a specific topic mentioned in this guide you might find some
of these resources helpful.

| Topic | Resource | Description |
|--------------|----------|-------------|
| Rust  | [Rust Book][rust-book] | If you are not yet comfortable with Rust, we highly suggest reading this book. |
| eBPF  | [Cilium BPF and XDP Reference Guide][cilium-guide] | If you are not yet comfortable with eBPF, this guide is excellent. |

## How to Use This Guide

This guide generally assumes that you’re reading it front-to-back. Later
chapters build on concepts in earlier chapters, and earlier chapters may
not dig into details on a topic, revisiting the topic in a later chapter.

## eBPF Program Constraints

The eBPF Virtual Machine, where our eBPF programs will be run, is a constrained
runtime environment:

- There is only 512 bytes of stack (or 256 bytes if we are using tail calls).
- There is no access to heap space and data must instead be written to maps.

Even applications written in C are restricted to a subset of language features,
and we have similar constraints in Rust:

- We may not use the standard library. We use `core` instead.
- `core::fmt` may not be used and neither can traits that rely on it, for
  example `Display` and `Debug`
- As there is no heap, we cannot use `alloc` or `collections`.
- We must not `panic` as the eBPF VM does not support stack unwinding, or the
  `abort` instruction.
- There is no `main` function

Alongside this, a lot of the code that we write is `unsafe`, as we are reading
directly from kernel memory.

[rust-book]: https://doc.rust-lang.org/book/
[cilium-guide]: https://docs.cilium.io/en/stable/bpf/
