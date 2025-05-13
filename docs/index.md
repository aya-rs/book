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

### [![Anza][anza-logo]{ width="150" }][anza]

Anza is using Aya with XDP in [Agave][agave], a [Solana][solana] validator
implementation. See more [here][agave-xdp-github].

### [![Deepfence][deepfence-logo]{ width="150" }][deepfence]

Deepfence is using Aya with XDP/TC as their packet filtering stack. See more
[here][deepfence-aya-article].

### [![Exein][exein-logo]{ width="150" }][exein]

Exein is using Aya in [Pulsar][pulsar], a Runtime Security Observability Tool
for IoT. See more [here][pulsar-github].

### [![Kubernetes SIGs][kubernetes-logo]{ width="150" }][kubernetes-sigs]

The [Kubernetes Special Interest Groups (SIGs)][kubernetes-sigs] are using Aya
to develop [Blixt][blixt], a load-balancer that supports the development and
maintenance of the [Gateway API project][gateway-api].

### [![Red Hat][redhat-logo]{ width="150" }][redhat]

Red Hat is using Aya to develop [bpfman][bpfman], an eBPF program loading daemon.

[agave]: https://github.com/anza-xyz/agave/
[agave-xdp-github]: https://github.com/anza-xyz/agave/tree/master/xdp
[anza-logo]: https://docs.anza.xyz/img/logo-horizontal.svg
[anza]: https://www.anza.xyz/
[solana]: https://solana.com/
[deepfence-logo]: https://uploads-ssl.webflow.com/63eaa07bbe370228bab003ea/640a069335cf3921e24def21_Deepfence%20Line.svg
[deepfence]: https://deepfence.io/
[deepfence-aya-article]: https://deepfence.io/aya-your-trusty-ebpf-companion/
[exein-logo]: https://blog.exein.io/content/images/2023/03/logoexein.png
[exein]: https://exein.io
[pulsar]: https://pulsar.sh/
[pulsar-github]: https://github.com/Exein-io/pulsar
[kubernetes-logo]: https://raw.githubusercontent.com/cncf/artwork/refs/heads/main/projects/kubernetes/horizontal/color/kubernetes-horizontal-color.svg
[kubernetes-sigs]: https://github.com/kubernetes-sigs
[blixt]: https://github.com/kubernetes-sigs/blixt
[gateway-api]: https://github.com/kubernetes-sigs/gateway-api
[redhat-logo]: https://www.redhat.com/cms/managed-files/Asset-Red_Hat-Logo_page-Logo-RGB.svg?itok=yWDK-rRz
[redhat]: https://redhat.com
[bpfman]: https://github.com/bpfman/bpfman
