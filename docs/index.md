# Home

eBPF is a technology that allows running user-supplied programs inside the Linux
kernel. For more info see https://ebpf.io/what-is-ebpf.

Aya is an eBPF library built with a focus on operability and developer
experience. It does not rely on [libbpf] nor [bcc] - it's built from the ground
up purely in Rust, using only the [libc] crate to execute syscalls. With BTF
support and when linked with musl, it offers a true [compile once, run
everywhere solution][co-re], where a single self-contained binary can be
deployed on many linux distributions and kernel versions.

Some of the major features provided include:

* Support for function call relocation and global data maps, which
  allows eBPF programs to make **function calls** and use **global variables
  and initializers**.
* **Async support** with both [tokio] and [async-std].
* Easy to deploy and fast to build: aya doesn't require a kernel build or
  compiled headers, and not even a C toolchain; a release build completes in a matter
  of seconds.
* Support for the **BPF Type Format** (BTF), which is transparently enabled when
  supported by the target kernel. This allows eBPF programs compiled against
  one kernel version to run on different kernel versions without the need to
  recompile.
  **This feature, however, is limited only to Aya as the loader of eBPF programs
  (in the userspace). The loaded eBPF program need to be compiled with clang.
  We don't support emitting BTF info and BTF relocations in eBPF programs
  compiled with Rust yet, although we are actively working on that.**
  [[0]](https://github.com/aya-rs/aya/issues/351)
  [[1]](https://github.com/aya-rs/aya/issues/349)

[libbpf]: https://github.com/libbpf/libbpf
[bcc]: https://github.com/iovisor/bcc
[libc]: https://docs.rs/libc
[co-re]: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
[tokio]: https://docs.rs/tokio
[async-std]: https://docs.rs/async-std

## Who's Using Aya

### [![Deepfence](https://deepfence.io/wp-content/themes/deepfence/public/img/logo.svg){ width="150"}](https://deepfence.io/)
Deepfence are using Aya with XDP/TC as their packet filtering stack. See more [here](https://deepfence.io/aya-your-trusty-ebpf-companion/).

### [![Exein](https://blog.exein.io/img/exein.gif){ width="150"}](https://exein.io)
Exein are using Aya in [Pulsar](https://pulsar.sh/), a Runtime Security Observability Tool for IoT. See more [here](https://blog.exein.io/pulsar).

### [![Parca](https://www.parca.dev/docs/img/logo.svg){ width="150"}](https://www.parca.dev/)
Parca are using Aya to write the BPF component of their profiler. See more [here](https://github.com/parca-dev/parca-agent/blob/main/bpf/cpu-profiler/src/main.rs).

### [![Red Hat](https://www.redhat.com/cms/managed-files/Asset-Red_Hat-Logo_page-Logo-RGB.svg?itok=yWDK-rRz){ width="150"}](https://redhat.com)
Red Hat are using Aya to develop [bpfd](https://github.com/redhat-et/bpfd), an eBPF program loading daemon.