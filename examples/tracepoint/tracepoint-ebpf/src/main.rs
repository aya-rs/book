#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 4096],
}

#[map]
pub static FILENAME_BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn tracepoint_execve(ctx: TracePointContext) -> u32 {
    match try_tracepoint_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_execve(ctx: TracePointContext) -> Result<u32, i32> {
    // To get the offset, see
    // /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
    const FILENAME_OFFSET: usize = 16;
    let filename_user_ptr: *const u8 = unsafe { ctx.read_at(FILENAME_OFFSET)? };
    let filename_buf = unsafe {
        let ptr = FILENAME_BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
            filename_user_ptr,
            &mut filename_buf.buf,
        )?)
    };
    let command = ctx.command()?;
    let command = unsafe { core::str::from_utf8_unchecked(&command) };
    info!(
        &ctx,
        "Tracepoint sys_enter_execve called by: {}, filename: {}",
        command,
        filename
    );

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
