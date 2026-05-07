#![no_std]
#![no_main]
#![allow(linker_messages)]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::info;

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

use vmlinux::kernel_clone_args;

const CLONE_THREAD: u64 = 0x00010000;

#[fentry]
pub fn fentry_clone(ctx: FEntryContext) -> u32 {
    let args_ptr: *const kernel_clone_args = ctx.arg(0);
    let flags = unsafe { (*args_ptr).flags };

    if flags & CLONE_THREAD == 0 {
        info!(
            &ctx,
            "Process creation is started by: {}",
            bpf_get_current_pid_tgid() as u32
        );
    }
    0
}

#[fexit]
pub fn fexit_clone(ctx: FExitContext) -> u32 {
    let args_ptr: *const kernel_clone_args = ctx.arg(0);
    let flags = unsafe { (*args_ptr).flags };
    let return_value: i32 = ctx.arg(1);

    if flags & CLONE_THREAD == 0 {
        info!(
            &ctx,
            "New process is created by: {} child id: {}",
            bpf_get_current_pid_tgid() as u32,
            return_value
        );
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
