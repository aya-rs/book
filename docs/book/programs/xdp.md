# XDP

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [on GitHub][source-code].

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

## Example project

Now that you have a little more understanding about XDP, let's follow up with a
practical example. We are going to write a simple XDP Program that drops
packets incoming from certain IPs.

### Setting up the development environment

Make sure you already have the [prerequisites][prerequisites].

Since we are writing an XDP program, we will use the XDP template (created with
`cargo generate`):

```console
cargo generate --name simple-xdp-program -d program_type=xdp \
    https://github.com/aya-rs/aya-template
```

### Creating the eBPF component

First, we must create the eBPF component for our program, in this component, we
will decide what to do with the incoming packets.

Since we want to drop the incoming packets from certain IPs, we are going to
use the `XDP_DROP` action code whenever the IP is in our blacklist, and
everything else will be treated with the `XDP_PASS` action code.

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
```

We import the necessary dependencies:

- `aya_ebpf`: For XDP actions (`bindings::xdp_action`), the XDP context struct
  `XdpContext` (`programs:XdpContext`), map definitions (for our HashMap) and
  XDP program macros (`macros::{map, xdp}`)
- `aya_log_ebpf`: For logging within the eBPF program
- `core::mem`: For memory manipulation
- `network_types`: For Ethernet and IP header definitions

> [!IMPORTANT]
> Make sure you add the `network_types` dependency in your `Cargo.toml`.

Here's how the code looks:

```rust
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

An eBPF-compatible panic handler is provided because
eBPF programs cannot use the default panic behavior.

```rust
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
```

Here, we define our blocklist with a `HashMap`,
which stores integers (u32), with a maximum of 1024 entries.

```rust
#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
```

The `xdp_firewall` function (picked up in user-space) accepts an `XdpContext`
and returns a `u32`. It delegates the main packet processing logic to the
`try_xdp_firewall` function. If an error occurs, the function returns
`xdp_action::XDP_ABORTED` (which is equal to the `u32` `0`).

```rust
#[inline(always)]
unsafe fn ptr_at<T>(
    ctx: &XdpContext, offset: usize
) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}
```

Our `ptr_at` function is designed to provide safe access to a generic type `T`
within an `XdpContext` at a specified offset. It performs bounds checking by
comparing the desired memory range (`start + offset + len`) against the end of
the data (`end`). If the access is within bounds, it returns a pointer to the
specified type; otherwise, it returns an error. We are going to use this
function to retrieve data from the `XdpContext`.

```rust

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    Ok(action)
}
```

The `block_ip` function checks if a given IP address (address) exists in the
blocklist.

As said before, the `try_xdp_firewall` contains the main logic for our firewall.
We first retrieve the Ethernet header from the `XdpContext` with the `ptr_at`
function, the header is located at the beginning of the `XdpContext`, therefore
we use `0` as an offset.

If the packet is not IPv4 (`ether_type` check), the function returns
`xdp_action::XDP_PASS` and allows the packet to pass through the network stack.

`ipv4hdr` is used to retrieve the IPv4 header, `source` is used to store the
source IP address from the IPv4 header. We then compare the IP address with
those that are in our blocklist using the `block_ip` function we created
earlier. If `block_ip` matches, meaning that the IP is in the blocklist, we use
the `XDP_DROP` action code so that it doesn't get through the network stack,
otherwise we let it pass with the `XDP_PASS` action code.

Lastly, we log the activity, `SRC` is the source IP address and `ACTION` is the
action code that has been used on it. We then return `Ok(action)` as a result.

The full code:

```rust
#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static IP_BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(
    ctx: &XdpContext, offset: usize,
) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn block_ip(address: u32) -> bool {
    unsafe { IP_BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }; 
    info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    Ok(action)
}
```

### Populating our map from user-space

In order to add the addresses to block, we first need to get a reference to the
`BLOCKLIST` map.

Once we have it, it's simply a case of calling `ip_blocklist.insert()` to
insert the ips into the blocklist.

We'll use the `IPv4Addr` type to represent our IP address as it's
human-readable and can be easily converted to a u32.

We'll block all traffic originating from `1.1.1.1` in this example.

> [!NOTE] Endianness
> IP addresses are always encoded in network byte order (big endian) within
> packets. In our eBPF program, before checking the blocklist, we convert them
> to host endian using `u32::from_be_bytes`. Therefore it's correct to write our
> IP addresses in host endian format from userspace.
>
> The other approach would work too: we could convert IPs to network endian
> when inserting from userspace, and then we wouldn't need to convert when
> indexing from the eBPF program.

Let's begin with writing the user-space code:

#### Importing dependencies

```rust
use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;
```

- `anyhow::Context`: Provides additional context for error handling
- `aya`: Provides the Bpf structure and related functions for loading eBPF
  programs, as well as the XDP program and its flags
  (`aya::programs::{Xdp, XdpFlags}`)
- `aya_log::EbpfLogger`: For logging within the eBPF program
- `clap::Parser`: Provides argument parsing
- `log::{info, warn}`: The [logging library][logging-library]
we use for informational and warning messages
- `std::net::Ipv4Addr`: A struct to work with IPv4 addresses
- `tokio::signal`: For handling signals asynchronously, see
  [this link][tokio-signal] for more information

> [!NOTE]
> `aya::Bpf` is deprecated since version `0.13.0` and `aya_log:BpfLogger`
> since `0.2.1`. Use [`aya::Ebpf`][aya-ebpf] and
> [`aya_log:EbpfLogger`][aya-ebpf-logger] instead if you are using the more
> recent versions.

#### Defining command-line arguments

```rust
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
```

A simple struct is defined for command-line parsing using
[clap's derive feature][clap-derive], with the optional argument `iface` to
provide our network interface name.

#### Main function

```rust
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/simple-xdp-program"
    )))?;
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - "
                    "try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    blocklist.insert(block_addr, 0, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
```

##### Parsing command-line arguments

Inside the `main` function, we first parse the command-line arguments,
using [`Opt::parse()`][clap-parse] and the struct defined earlier.

##### Initializing environment logging

Logging is initialized using [`env_logger::init()`][env-logger-init], we will
make use of the environment logger later in our code.

##### Loading the eBPF program

The eBPF program is loaded using `Ebpf::load()`, choosing the debug or release
version based on the build configuration (`debug_assertions`).

##### Loading and attaching our XDP

The XDP program named `xdp_firewall` is retrieved from the eBPF program we
defined earlier using `bpf.program_mut()`. The XDP program is then loaded and
attached to our network interface.

##### Setting up the IP blocklist

The IP blocklist (`BLOCKLIST` map) is loaded from the eBPF program and
converted to a `HashMap`. The IP `1.1.1.1` is added to the blocklist.

##### Waiting for the exit signal

The program awaits the `CTRL+C` signal asynchronously using
`signal::ctrl_c().await`, once received, it logs an exit message and returns
`Ok(())`.

#### Full user-space code

```rust
use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/simple-xdp-program"
    )))?;
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut Xdp =
        bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - "
                    "try changing XdpFlags::default() to "
                    "XdpFlags::SKB_MODE")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    blocklist.insert(block_addr, 0, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
```

### Running our program

Now that we have all the pieces for our eBPF program, we can run it using:

```console
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

or

```console
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- \
  --iface <interface>
```

if you want to provide another network interface name. note that you can also
omit `RUST_LOG=info`, but you won't get any logging.

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-drop
[af-xdp]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[kernel-documentation]: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
[cilium-xdp]: https://docs.cilium.io/en/latest/bpf/progtypes/#xdp
[prerequisites]: https://aya-rs.dev/book/start/development/
[logging-library]: https://docs.rs/log/latest/log/index.html
[tokio-signal]: https://docs.rs/tokio/latest/tokio/signal/
[aya-ebpf]: https://docs.aya-rs.dev/aya/struct.ebpf
[aya-ebpf-logger]: https://docs.aya-rs.dev/aya_log/struct.ebpflogger
[clap-derive]: https://docs.rs/clap/latest/clap/_derive/index.html
[clap-parse]: https://docs.rs/clap/latest/clap/trait.Parser.html#method.parse
[env-logger-init]: https://docs.rs/env_logger/latest/env_logger/fn.init.html
