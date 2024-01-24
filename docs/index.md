# Home

eBPF is a technology that allows running user-supplied programs inside the Linux
kernel. For more info see the ["What is eBPF?" documentation][what-is-ebpf].

Aya is an eBPF library built with a focus on operability and developer
experience. It does not rely on [libbpf] nor [bcc] - it's built from the ground
up purely in Rust, using only the [libc] crate to execute syscalls. With BTF
support and when linked with musl, it offers a true [compile once, run
everywhere solution][co-re], where a single self-contained binary can be
deployed on many linux distributions and kernel versions.

Some of the major features provided include:

* Support for the **BPF Type Format** (BTF), which is transparently enabled when
  supported by the target kernel. This allows eBPF programs compiled against
  one kernel version to run on different kernel versions without the need to
  recompile.
* Support for function call relocation and global data maps, which
  allows eBPF programs to make **function calls** and use **global variables
  and initializers**.
* **Async support** with both [tokio] and [async-std].
* Easy to deploy and fast to build: aya doesn't require a kernel build or
  compiled headers, and not even a C toolchain; a release build completes in a matter
  of seconds.

[what-is-ebpf]:https://ebpf.io/what-is-ebpf
[libbpf]: https://github.com/libbpf/libbpf
[bcc]: https://github.com/iovisor/bcc
[libc]: https://docs.rs/libc
[co-re]: https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
[tokio]: https://docs.rs/tokio
[async-std]: https://docs.rs/async-std

## Who's Using Aya

### [![Deepfence](https://uploads-ssl.webflow.com/63eaa07bbe370228bab003ea/640a069335cf3921e24def21_Deepfence%20Line.svg){ width="150"}](https://deepfence.io/)
Deepfence is using Aya with XDP/TC as their packet filtering stack. See more [here](https://deepfence.io/aya-your-trusty-ebpf-companion/).

### [![Exein](https://blog.exein.io/content/images/2023/03/logoexein.png){ width="150"}](https://exein.io)
Exein is using Aya in [Pulsar](https://pulsar.sh/), a Runtime Security Observability Tool for IoT. See more [here](https://github.com/Exein-io/pulsar).

### [![Kubernetes SIGs](https://github.com/aya-rs/book/assets/5332524/abde6552-10ed-4c52-9717-732d1ec7ea6c){ width="150" }](https://github.com/kubernetes-sigs)
The [Kubernetes Special Interest Groups (SIGs)](https://github.com/kubernetes-sigs) are using Aya to develop
[Blixt](https://github.com/kubernetes-sigs/blixt), a load-balancer that supports the development and maintenance
of the [Gateway API project](https://github.com/kubernetes-sigs/gateway-api).

### [![Red Hat](https://www.redhat.com/cms/managed-files/Asset-Red_Hat-Logo_page-Logo-RGB.svg?itok=yWDK-rRz){ width="150"}](https://redhat.com)
Red Hat is using Aya to develop [bpfman](https://github.com/bpfman/bpfman), an eBPF program loading daemon.
