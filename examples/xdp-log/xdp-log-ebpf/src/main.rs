#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    l2::eth::{EthHdr, EthProto, ETH_HDR_LEN},
    l3::ip::{Ipv4Hdr, Ipv4Proto, IPV4_HDR_LEN},
    l4::{tcp::TcpHdr, udp::UdpHdr},
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // (2)
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.proto {
        EthProto::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
    let source_addr = unsafe { *ipv4hdr }.source;

    let source_port = match unsafe { *ipv4hdr }.proto {
        Ipv4Proto::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN) }?;
            u16::from_be(unsafe { *tcphdr }.source)
        }
        Ipv4Proto::Udp => {
            let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN) }?;
            u16::from_be(unsafe { *udphdr }.source)
        }
        _ => return Err(()),
    };

    info!(
        &ctx,
        "SRC IP: {:ipv4}, SRC PORT: {}", source_addr, source_port
    );

    Ok(xdp_action::XDP_PASS)
}
