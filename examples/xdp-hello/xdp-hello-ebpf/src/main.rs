#![no_std] // (1)
#![no_main] // (2)
#![no_builtins] // (3)

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp] // (5)
pub fn xdp_hello(ctx: XdpContext) -> u32 {
    // (6)
    match unsafe { try_xdp_hello(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_xdp_hello(ctx: XdpContext) -> Result<u32, u32> {
    // (7)
    info!(&ctx, "received a packet");
    // (8)
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler] // (4)
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
