#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

// (1)
const MAX_PATH: usize = 4096; 

// (2)
#[repr(C)]
pub struct Buf {
    pub buf: [u8; MAX_PATH],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0); // (3)

#[tracepoint]
pub fn aya_tracepoint_echo_open(ctx: TracePointContext) -> u32 {
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
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?; // (4)
            &mut *ptr
        };

        // read the filename
        let filename = unsafe {
            core::str::from_utf8_unchecked(
                bpf_probe_read_user_str_bytes(  // (5)
                    filename_addr as *const u8,
                    &mut buf.buf,
                )?
            )
        };

        if filename.len() < MAX_PATH {  // (6)
            // log the filename
            info!(
                &ctx,
                "Kernel tracepoint sys_enter_openat called,  filename {}", filename
            );
        }
    }

    Ok(0)
}

fn try_aya_tracepoint_echo_open_2(ctx: TracePointContext) -> Result<u32, i64> {
    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;

    let maybe_filename_or_err = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) }
        .and_then(|r| unsafe {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
            Ok((r, &mut *ptr))
        })
        .and_then(|tuple_of_address_and_buffer| unsafe {
            Ok(bpf_probe_read_user_str_bytes(
                tuple_of_address_and_buffer.0 as *const u8,
                &mut tuple_of_address_and_buffer.1.buf,
            )?)
        })
        .and_then(|pathstring_as_bytes| {
            Ok(unsafe { core::str::from_utf8_unchecked(pathstring_as_bytes) })
        });

    match maybe_filename_or_err {
        Ok(f) => {
            if f.len() < MAX_PATH {
                // log the filename
                info!(
                    &ctx,
                    "Kernel tracepoint sys_enter_openat called,  filename {}", f
                );
            };
            Ok(0)
        }
        Err(e) => Err(e),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
