#![no_std]
#![no_main]

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

use aya_ebpf::{
    cty::{c_int, c_ulong},
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};

use vmlinux::task_struct;

#[map]
static PROCESSES: HashMap<i32, i32> = HashMap::with_max_entries(32768, 0);

#[lsm(hook = "task_alloc")]
pub fn task_alloc(ctx: LsmContext) -> i32 {
    match unsafe { try_task_alloc(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
    let (pid, _clone_flags, retval): (_, c_ulong, c_int) = unsafe {
        let task: *const task_struct = ctx.arg(0);
        ((*task).pid, ctx.arg(1), ctx.arg(2))
    };
    // Save the PID of a new process in map.
    PROCESSES.insert(&pid, &pid, 0).map_err(|e| e as i32)?;

    // Handle results of previous LSM programs.
    if retval != 0 {
        return Ok(retval);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
