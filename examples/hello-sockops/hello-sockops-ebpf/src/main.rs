#![no_std]
#![no_main]

use aya_ebpf::{macros::sock_ops, programs::SockOpsContext, EbpfContext};
use aya_log_ebpf::{info, warn};

// Cannot do `cargo add libc` due to no_std.
const AF_INET: u32 = 2;

#[sock_ops]
pub fn socket_ops(ctx: SockOpsContext) -> u32 {
    match try_socket_ops(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_socket_ops(ctx: SockOpsContext) -> Result<u32, i64> {
    // `ctx.op()` specifies the type of operation this eBPF program should perform.
    // So a sock_ops program will often start by matching on it.
    info!(&ctx, "started..");
    if ctx.family() == AF_INET {
        let local_ipv4_addr = ctx.local_ip4();
        let local_port = ctx.local_port();
        let pid = ctx.pid();
        warn!(
            &ctx,
            "PID {} | from {}:{} | op {}",
            pid,
            local_ipv4_addr,
            local_port,
            ctx.op()
        );
    }

    // From https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS
    // the program should return 1 on success.
    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
