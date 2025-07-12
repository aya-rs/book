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

use crate::vmlinux::{sock, sock_common};

use aya_ebpf::{
    helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext,
};
use aya_log_ebpf::info;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
    }?;
    match sk_common.skc_family {
        AF_INET => {
            let src_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
            });
            let dest_addr: u32 = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
            });
            info!(
                &ctx,
                "AF_INET src address: {:i}, dest address: {:i}",
                src_addr,
                dest_addr,
            );
            Ok(0)
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6 src addr: {:i}, dest addr: {:i}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
