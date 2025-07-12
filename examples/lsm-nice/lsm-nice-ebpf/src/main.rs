#![no_std]
#![no_main]

use aya_ebpf::{cty::c_int, macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

// (1)
#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use vmlinux::task_struct;

// (2)
/// PID of the process for which setting a negative nice value is denied.
#[unsafe(no_mangle)]
static PID: i32 = 0;

#[lsm(hook = "task_setnice")]
pub fn task_setnice(ctx: LsmContext) -> i32 {
    match unsafe { try_task_setnice(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// (3)
unsafe fn try_task_setnice(ctx: LsmContext) -> Result<i32, i32> {
    let (pid, nice, ret, global_pid): (c_int, c_int, c_int, c_int) = unsafe {
        let p: *const task_struct = ctx.arg(0);
        (
            (*p).pid,
            ctx.arg(1),
            ctx.arg(2),
            core::ptr::read_volatile(&PID),
        )
    };

    info!(
        &ctx,
        "The PID supplied to this program is: {}, with nice value {} and return value {}. Monitoring for changes in PID: {}",
        pid,
        nice,
        ret,
        global_pid
    );
    if ret != 0 {
        return Err(ret);
    }

    if pid == global_pid && nice < 0 {
        return Err(-1);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
