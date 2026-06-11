# Redirecting with AF_XDP

> [!NOTE]
> Full code for the example in this chapter is available [on GitHub][source-code].

In the [blocklist example](xdp-blocklist.md) the XDP program decided the fate of
each packet entirely in the kernel. Sometimes, though, we want to hand a packet
to user-space for processing without paying the cost of traversing the whole
network stack. This is exactly what `XDP_REDIRECT` together with an
[`AF_XDP`][af-xdp] socket gives us.

In this example we build a tiny ICMP "ping" responder. The XDP program matches
incoming ICMP echo requests and redirects them into an `AF_XDP` socket. A
user-space program then reads those packets, turns each request into an echo
reply, and sends it straight back out.

## AF_XDP sockets and queues

An `AF_XDP` socket is a socket type that lets
user-space send and receive raw frames directly from a network interface,
bypassing the kernel network stack. Frames are exchanged through a shared memory
region (the *UMEM*) using a set of ring buffers: an RX and a TX ring for
receiving and transmitting, plus a fill and a completion ring used to pass empty
and used buffers back and forth with the kernel.

A network interface spreads incoming traffic across several hardware *RX queues*
so it can be handled by multiple CPU cores in parallel. An `AF_XDP` socket is
bound to a single queue, so to receive from every queue we open
one socket per queue and register each of them with the XDP program.

## How it works

The data path has two halves:

- **eBPF**: an XDP program inspects every packet and, for ICMP echo requests,
  redirects them into a socket map (`XskMap`). Everything else is passed on with
  `XDP_PASS`.
- **User-space**: for every RX queue we open an `AF_XDP` socket, register its
  file descriptor in the `XskMap`, and run a loop that receives redirected
  packets, rewrites them into echo replies and transmits them.

We use the [`xsk-rs`][xsk-rs] crate for the user-space `AF_XDP` plumbing
(UMEM and the fill/completion/RX/TX queues).

## The eBPF component

We define a single map, an `XskMap` named `SOCKS`. This is the map the kernel
uses to look up which `AF_XDP` socket a packet should be redirected to.

```rust,ignore
#[map]
static SOCKS: XskMap = XskMap::with_max_entries(8, 0);
```

> [!NOTE]
> The map has 8 entries because the user-space side opens one socket per RX
> queue and we assume at most 8 queues. The two numbers must agree.

The program parses the Ethernet, IPv4 and ICMP headers and only redirects
packets that are ICMP echo requests.

```rust,ignore
fn try_xdp_ping(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            // Get protocol type from ip header
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let protocol = unsafe { (*ipv4hdr).proto().map_err(|_| ())? };
            if protocol != IpProto::Icmp {
                return Ok(xdp_action::XDP_PASS);
            }

            // Ignore ip packets with options
            if unsafe { (*ipv4hdr).options_len() } > 0 {
                return Ok(xdp_action::XDP_PASS);
            }

            // Get ICMP type and code
            let icmp_hdr: *const Icmpv4Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            let msg_type: Icmpv4Type =
                unsafe { (*icmp_hdr).icmp_type().map_err(|_| ())? };
            if matches!(msg_type, Icmpv4Type::Echo) {
                info!(&ctx, "Got a message in XDP. Forwarding");
                Ok(SOCKS
                    .redirect(ctx.rx_queue_index(), 0)
                    .unwrap_or(xdp_action::XDP_PASS))
            } else {
                Ok(xdp_action::XDP_PASS)
            }
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}
```

The key call is `SOCKS.redirect(ctx.rx_queue_index(), 0)`. We index the map by
the RX queue the packet arrived on, so a packet from queue `N` is delivered to
the socket we registered for queue `N`. If there is no socket for that queue,
`redirect` fails and we fall back to `XDP_PASS`.

## The user-space component

The user-space program is responsible for three things: opening one `AF_XDP`
socket per RX queue, registering those sockets in the `SOCKS` map, and running a
receive/transmit loop per socket.

### Loading the program and registering the sockets

After loading and attaching the XDP program we open the sockets and register
each socket's RX queue file descriptor in the `SOCKS` map, keyed by queue index.
This is the user-space counterpart of the `SOCKS.redirect(...)` call in the eBPF
program.

```rust,ignore
let program: &mut Xdp = bpf.program_mut("xdp_ping").unwrap().try_into()?;
program.load()?;
program.attach(&opt.iface, XdpMode::default())?;

// Create AF_XDP sockets
let queue_cnt: u32 = 8;
let socket_resources = setup_sockets(&opt.iface, queue_cnt)?;

// Create sockets map
let mut sockets_map: XskMap<_> = XskMap::try_from(
    bpf.map_mut("SOCKS").context("Unable to load sockets map")?,
)?;

// Load RX queue descriptors into the sockets map
for queue_idx in 0..queue_cnt {
    sockets_map.set(
        queue_idx,
        socket_resources[queue_idx as usize].rx_q.fd().as_raw_fd(),
        0,
    )?;
}
```

### The receive/transmit loop

Each socket is driven by its own thread running `run_queue_loop`. The loop polls
the RX queue, rewrites every received packet into an echo reply, transmits them,
and finally recycles the completed frame descriptors back into the fill queue so
they can be reused.

```rust,ignore
fn run_queue_loop(
    mut socket: SocketResources,
    cancellation: &AtomicBool,
) -> anyhow::Result<()> {
    let mut descs = vec![FrameDesc::default(); socket.frame_cnt as usize];
    while !cancellation.load(Ordering::Relaxed) {
        let packet_cnt =
            unsafe { socket.rx_q.poll_and_consume(&mut descs, 100)? };

        for desc in &mut descs[..packet_cnt] {
            let mut data = unsafe { socket.umem.data_mut(desc) };
            let pkt = data.contents_mut();
            create_reply(pkt);
        }

        unsafe { socket.tx_q.produce(&descs[..packet_cnt]) };

        // move descriptors from completion into fill
        let comp_cnt = unsafe { socket.comp_q.consume(&mut descs) };
        unsafe { socket.fill_q.produce(&descs[..comp_cnt]) };
    }
    Ok(())
}
```

### Turning a request into a reply

`create_reply` does the actual packet rewriting. Because the eBPF program
already guaranteed the packet is an ICMP echo request over IPv4 with no IP
options, we can rewrite it in place without re-validating anything.

To turn an echo request into an echo reply we:

1. swap the source and destination MAC addresses,
2. swap the source and destination IP addresses,
3. change the ICMP type from echo request (`8`) to echo reply (`0`),
4. fix up the ICMP checksum.

```rust,ignore
fn create_reply(pkt: &mut [u8]) {
    let (eth_hdr, ip_packet) = pkt.split_at_mut(EthHdr::LEN);

    // swap mac addresses
    let [eth_dst, eth_src] = eth_hdr.get_disjoint_mut([0..6, 6..12]).unwrap();
    eth_src.swap_with_slice(eth_dst);

    let (ip_header, icmp_packet) = ip_packet.split_at_mut(Ipv4Hdr::LEN);

    // swap ip addresses
    let [ip_src, ip_dst] = ip_header.get_disjoint_mut([12..16, 16..20]).unwrap();
    ip_src.swap_with_slice(ip_dst);

    icmp_packet[0] = Icmpv4Type::EchoReply as u8;

    // Recompute checksum. RFC 1624
    let mut sum = u16::from_be_bytes([icmp_packet[2], icmp_packet[3]]) as u32;
    sum += 0x0800;
    sum = (sum & 0xffff) + (sum >> 16);
    icmp_packet[2..4].copy_from_slice(&(sum as u16).to_be_bytes());
}
```

## Running the program

```console
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- \
  --iface <interface>
```

## Example output

```console
[2026-06-11T21:22:15Z INFO  xdp_redirect] Waiting for Ctrl-C...
[2026-06-11T21:22:30Z INFO  xdp_redirect] Got 1 messages
[2026-06-11T21:22:30Z INFO  xdp_redirect] Got a message in XDP. Forwarding
[2026-06-11T21:22:30Z INFO  xdp_redirect] Replying to 1 messages!
[2026-06-11T21:22:30Z INFO  xdp_redirect] Got 1 messages
[2026-06-11T21:22:30Z INFO  xdp_redirect] Replying to 1 messages!
[2026-06-11T21:22:30Z INFO  xdp_redirect] Got a message in XDP. Forwarding
```

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-redirect
[af-xdp]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[xsk-rs]: https://docs.rs/xsk-rs/latest/xsk_rs/
