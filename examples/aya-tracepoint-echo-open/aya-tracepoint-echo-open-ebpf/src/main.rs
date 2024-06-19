#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

// (4)
const MAX_PATH: usize = 4096; 

// (5)
#[repr(C)]
pub struct Buf {
    pub buf: [u8; MAX_PATH],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0); // (6)

#[tracepoint]
pub fn aya_tracepoint_echo_open(ctx: TracePointContext) -> u32 {
    // match try_aya_tracepoint_echo_open_small_file_path(ctx: TracePointContext) { // (1)
    match try_aya_tracepoint_echo_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_aya_tracepoint_echo_open(ctx: TracePointContext) -> Result<u32, i64> {
    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;

    if let Ok(filename_addr) = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) } {
        // get the map-backed buffer that we're going to use as storage for the filename
        let buf = unsafe {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?; // (7)
            &mut *ptr
        };

        // read the filename
        let filename = unsafe {
            core::str::from_utf8_unchecked(
                bpf_probe_read_user_str_bytes(  // (8)
                    filename_addr as *const u8,
                    &mut buf.buf,
                )?
            )
        };

        if filename.len() < MAX_PATH {
            // log the filename
            info!(
                &ctx,
                "Kernel tracepoint sys_enter_openat called,  filename {}", filename
            );
        }
    }
    Ok(0)
}

// This function assumes that the maximum length of a file's path can be of 16 bytes. This is meant
// to be read as an example, only. Refer to the accompanying `tracepoints.md` for its inclusion in the
// code.
fn try_aya_tracepoint_echo_open_small_file_path(ctx: TracePointContext) -> Result<u32, i64> { // (2)
    const MAX_SMALL_PATH: i32 = 16;
    let mut buf: [u8; MAX_SMALL_PATH] = [0; MAX_SMALL_PATH];

    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;
    if let Ok(filename_addr) = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) } {
        // read the filename
        let filename = unsafe {
            // Get an UTF-8 String from an array of bytes
            core::str::from_utf8_unchecked(
                // Use the address of the kernel's string  // (3)
                // to copy its contents into the array named 'buf'
                match bpf_probe_read_user_str_bytes (
                    filename_addr as *const u8,
                    &mut buf,
                ) {
                    Ok(_) =>  &buf,
                    Err(e)  => {
                        info!(&ctx, "tracepoint sys_enter_openat called buf_probe failed {}", e);
                        return Err(e);
                    },
                }
            )
        };
        info!(&ctx, "tracepoint sys_enter_openat called, filename  {}", filename);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
