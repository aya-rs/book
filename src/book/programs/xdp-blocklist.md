# Blocklist Firewall

> [!NOTE]
> Full code for the example in this chapter is available [on GitHub][source-code].

In this chapter we write a simple XDP program that drops packets arriving from a
set of blocked IP addresses: any packet from a blocked address is dropped with
`XDP_DROP`, while everything else is allowed through with `XDP_PASS`. If you need
a refresher on XDP itself, see the [XDP overview](xdp.md).

## Setting up the development environment

Make sure you already have the [prerequisites][prerequisites].

Since we are writing an XDP program, we will use the XDP template (created with
`cargo generate`):

```console
cargo generate --name simple-xdp-program -d program_type=xdp \
    https://github.com/aya-rs/aya-template
```

## Creating the eBPF component

First, we must create the eBPF component for our program, in this component, we
will decide what to do with the incoming packets.

Since we want to drop the incoming packets from certain IPs, we are going to
use the `XDP_DROP` action code whenever the IP is in our blacklist, and
everything else will be treated with the `XDP_PASS` action code.

```rust,ignore
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

```rust,ignore
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

An eBPF-compatible panic handler is provided because
eBPF programs cannot use the default panic behavior.

```rust,ignore
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
```

Here, we define our blocklist with a `HashMap`,
which stores integers (u32), with a maximum of 1024 entries.

```rust,ignore
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

```rust,ignore
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

```rust,ignore
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

```rust,ignore
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

## Populating our map from user-space

In order to add the addresses to block, we first need to get a reference to the
`BLOCKLIST` map.

Once we have it, it's simply a case of calling `ip_blocklist.insert()` to
insert the ips into the blocklist.

We'll use the `IPv4Addr` type to represent our IP address as it's
human-readable and can be easily converted to a u32.

We'll block all traffic originating from `1.1.1.1` in this example.

> [!NOTE]
> IP addresses are always encoded in network byte order (big endian) within
> packets. In our eBPF program, before checking the blocklist, we convert them
> to host endian using `u32::from_be_bytes`. Therefore it's correct to write our
> IP addresses in host endian format from userspace.
>
> The other approach would work too: we could convert IPs to network endian
> when inserting from userspace, and then we wouldn't need to convert when
> indexing from the eBPF program.

Let's begin with writing the user-space code:

### Importing dependencies

```rust,ignore
use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;
```

- `anyhow::Context`: Provides additional context for error handling
- `aya`: Provides the Bpf structure and related functions for loading eBPF
  programs, as well as the XDP program and attach mode
  (`aya::programs::{Xdp, XdpMode}`)
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

### Defining command-line arguments

```rust,ignore
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
```

A simple struct is defined for command-line parsing using
[clap's derive feature][clap-derive], with the optional argument `iface` to
provide our network interface name.

### Main function

```rust,ignore
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
    program.attach(&opt.iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - "
                    "try changing XdpMode::default() to XdpMode::Skb")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    blocklist.insert(block_addr, 0, 0)?;

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
```

#### Parsing command-line arguments

Inside the `main` function, we first parse the command-line arguments,
using [`Opt::parse()`][clap-parse] and the struct defined earlier.

#### Initializing environment logging

Logging is initialized using [`env_logger::init()`][env-logger-init], we will
make use of the environment logger later in our code.

#### Loading the eBPF program

The eBPF program is loaded using `Ebpf::load()`, choosing the debug or release
version based on the build configuration (`debug_assertions`).

#### Loading and attaching our XDP

The XDP program named `xdp_firewall` is retrieved from the eBPF program we
defined earlier using `bpf.program_mut()`. The XDP program is then loaded and
attached to our network interface.

#### Setting up the IP blocklist

The IP blocklist (`BLOCKLIST` map) is loaded from the eBPF program and
converted to a `HashMap`. The IP `1.1.1.1` is added to the blocklist.

#### Waiting for the exit signal

The program awaits the `CTRL+C` signal asynchronously using
`signal::ctrl_c().await`, once received, it logs an exit message and returns
`Ok(())`.

### Full user-space code

```rust,ignore
use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
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
    program.attach(&opt.iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - "
                    "try changing XdpMode::default() to "
                    "XdpMode::Skb")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    blocklist.insert(block_addr, 0, 0)?;

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
```

## Running our program

Now that we have all the pieces for our eBPF program, we can run it using:

```console
RUST_LOG=info cargo run
```

or

```console
RUST_LOG=info cargo run -- \
  --iface <interface>
```

if you want to provide another network interface name. note that you can also
omit `RUST_LOG=info`, but you won't get any logging.

[source-code]: https://github.com/aya-rs/book/tree/main/examples/xdp-drop
[prerequisites]: https://aya-rs.dev/book/start/development/
[logging-library]: https://docs.rs/log/latest/log/index.html
[tokio-signal]: https://docs.rs/tokio/latest/tokio/signal/
[aya-ebpf]: https://docs.aya-rs.dev/aya/struct.ebpf
[aya-ebpf-logger]: https://docs.aya-rs.dev/aya_log/struct.ebpflogger
[clap-derive]: https://docs.rs/clap/latest/clap/_derive/index.html
[clap-parse]: https://docs.rs/clap/latest/clap/trait.Parser.html#method.parse
[env-logger-init]: https://docs.rs/env_logger/latest/env_logger/fn.init.html
