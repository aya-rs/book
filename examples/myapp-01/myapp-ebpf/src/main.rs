/* ANCHOR: all */
#![no_std]
#![no_main]

// ANCHOR: use
use aya_bpf::bindings::xdp_action;
use aya_bpf::cty::c_long;
use aya_bpf::macros::xdp;
use aya_bpf::programs::XdpContext;
// ANCHOR_END: use

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

// ANCHOR: main
#[xdp(name="myapp")]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_firewall(_ctx: XdpContext) -> Result<u32, c_long> {
    Ok(xdp_action::XDP_PASS)
}
// ANCHOR_END: main
/* ANCHOR_END: all */