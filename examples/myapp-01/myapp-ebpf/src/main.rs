#![no_std] // (1)
#![no_main] // (2)

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp(name = "myapp")] // (4)
pub fn myapp(ctx: XdpContext) -> u32 {
    // (5)
    match unsafe { try_myapp(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_myapp(_ctx: XdpContext) -> Result<u32, u32> {
    // (6)
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler] // (3)
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
