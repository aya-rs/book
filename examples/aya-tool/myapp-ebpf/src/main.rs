#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
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
    let task: *const task_struct = ctx.arg(0);
    let _clone_flags: c_ulong = ctx.arg(1);
    let retval: c_int = ctx.arg(2);

    // Save the PID of a new process in map.
    let pid = (*task).pid;
    PROCESSES.insert(&pid, &pid, 0).map_err(|e| e as i32)?;

    // Handle results of previous LSM programs.
    if retval != 0 {
        return Ok(retval);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
