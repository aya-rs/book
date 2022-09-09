#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{HashMap, PerfEventArray},
    programs::TcContext,
};
use memoffset::offset_of;

use tc_egress_common::PacketLog;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST")] // (1)
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier(name = "tc_egress")]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

// (2)
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, i64> {
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    if h_proto != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }
    let destination =
        u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);

    // (3)
    let action = if block_ip(destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    let log_entry = PacketLog {
        ipv4_address: destination,
        action: action,
    };
    unsafe {
        EVENTS.output(&ctx, &log_entry, 0);
    }
    Ok(action)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
