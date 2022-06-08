#![no_std]
#![no_main]

use aya_bpf::{cty::c_int, macros::lsm, programs::LsmContext};

// (1)
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::task_struct;

// (2)
/// PID of the process for which setting a negative nice value is denied.
#[no_mangle]
static PID: i32 = 0;

#[lsm(name = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {
    match unsafe { try_task_setnice(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// (3)
unsafe fn try_task_setnice(ctx: LsmContext) -> Result<i32, i32> {
    let p: *const task_struct = ctx.arg(0);
    let nice: c_int = ctx.arg(1);
    let ret: c_int = ctx.arg(2);

    // If previous eBPF LSM program didn't allow the action, return the
    // previous error code.
    if ret != 0 {
        return Err(ret);
    }

    // Deny setting the nice value lower than 0 for the defined PID.
    if (*p).pid == core::ptr::read_volatile(&PID) && nice < 0 {
        return Err(-1);
    }

    // Otherwise allow it.
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
