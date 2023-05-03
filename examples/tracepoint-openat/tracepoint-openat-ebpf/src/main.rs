#![no_std]
#![no_main]

use aya_bpf::{bpf_printk, macros::tracepoint, programs::TracePointContext};
use aya_bpf::cty::c_char;
use aya_log_ebpf::info;

/*
name: sys_enter_openat
ID: 638
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int dfd;	offset:16;	size:8;	signed:0;
	field:const char * filename;	offset:24;	size:8;	signed:0;
	field:int flags;	offset:32;	size:8;	signed:0;
	field:umode_t mode;	offset:40;	size:8;	signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx",
    ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)),
    ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
*/

#[tracepoint(name = "tracepoint_openat")]
pub fn tracepoint_openat(ctx: TracePointContext) -> u32 {
    match try_tracepoint_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracepoint_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let file_name: *const c_char = unsafe { ctx.read_at(24).unwrap() };

    unsafe { bpf_printk!(b"file_name: %s", file_name) };

    info!(&ctx, "tracepoint sys_enter_openat called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
