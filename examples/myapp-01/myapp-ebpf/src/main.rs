// ANCHOR: all
#![no_std]
#![no_main]

// ANCHOR: use
use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
// ANCHOR_END: use

// ANCHOR: main
#[xdp(name="myapp")]
pub fn myapp(ctx: XdpContext) -> u32 {
    match unsafe { try_myapp(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_myapp(_ctx: XdpContext) -> Result<u32, u32> {
    Ok(xdp_action::XDP_PASS)
}
// ANCHOR_END: main

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
// ANCHOR_END: all
