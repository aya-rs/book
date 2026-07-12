# XDP

## What is XDP in eBPF?

XDP (eXpress Data Path) is a type of eBPF program that attaches to the network
interface. It enables filtering, manipulation and redirection of network
packets as soon as they are received from the network driver, even before they
enter the Linux kernel networking stack, resulting in low latency and high
throughput.

The idea behind XDP is to add an early hook in the `RX` path of the kernel,
and let a user supplied eBPF program decide the fate of the packet.
The hook is placed in the NIC driver just after the interrupt processing,
and before any memory allocation needed by the network stack itself.

The XDP program is allowed to edit the packet data and,
after the XDP program returns, an action code determines what to do with the
packet:

- `XDP_PASS`: let the packet continue through the network stack
- `XDP_DROP`: silently drop the packet
- `XDP_ABORTED`: drop the packet with trace point exception
- `XDP_TX`: bounce the packet back to the same NIC it arrived on
- `XDP_REDIRECT`: redirect the packet to another NIC or user space socket via
  the [`AF_XDP`][af-xdp] address family

## AF_XDP

Along with XDP, a new address familiy entered in the Linux kernel, starting at
4.18. `AF_XDP`, formerly known as `AF_PACKETv4` (which was never included in
the mainline kernel), is a raw socket optimized for high performance packet
processing and allows zero-copy between kernel and applications. As the socket
can be used for both receiving and transmitting, it supports high performance
network applications purely in user-space.

If you want a more extensive explanation about `AF_XDP`, you can find it in the
[kernel documentation][kernel-documentation].

For a worked example, see [Redirecting with AF_XDP](xdp-redirect.md).

## XDP operation modes

You can connect an XDP program to an interface using the following modes:

### Generic XDP

- XDP programs are loaded into the kernel as part of the ordinary network path
- Doesn't need support from the network card driver to function
- Doesn't provide full performance benefits
- Easy way to test XDP programs

### Native XDP

- XDP programs are loaded by the network card driver as part of its initial
  receive path
- Requires support from the network card driver to function
- Default operation mode

### Offloaded XDP

- XDP programs are loaded directly on the NIC, and executed without using the CPU
- Requires support from the NIC

## Driver support for native XDP

For more information, please visit the [Cilium XDP documentation][cilium-xdp]
under `Drivers supporting native XDP`.

## Driver support for offloaded XDP

Currently, only the Netronome NFP drivers have support for offloaded XDP.

## Examples

The following chapters walk through complete XDP programs:

- [Blocklist Firewall](xdp-blocklist.md): drop packets coming from selected IP
  addresses.
- [Redirecting with AF_XDP](xdp-redirect.md): redirect packets into a user-space
  `AF_XDP` socket and reply to them from user-space.

[af-xdp]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[kernel-documentation]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[cilium-xdp]: https://docs.cilium.io/en/latest/bpf/progtypes/#xdp
