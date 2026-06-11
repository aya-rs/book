#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::{Icmpv4Hdr, Icmpv4Type},
    ip::{IpProto, Ipv4Hdr},
};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(8, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let (start, end) = (ctx.data(), ctx.data_end());
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

#[xdp]
pub fn xdp_ping(ctx: XdpContext) -> u32 {
    try_xdp_ping(ctx).unwrap_or_else(|_| xdp_action::XDP_PASS)
}

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
