#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::{HashMap, PerfEventArray},
    programs::SkBuffContext,
};
use memoffset::offset_of;
use network_types::ip::Ipv4Hdr;

use cgroup_skb_egress_common::PacketLog;

#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::new(0);

#[map] // (1)
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
    try_cgroup_skb_egress(ctx).unwrap_or(0)
}

// (2)
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_cgroup_skb_egress(ctx: SkBuffContext) -> Result<i32, i64> {
    let protocol = unsafe { (*ctx.skb.skb).protocol };
    if protocol != ETH_P_IP {
        return Ok(1);
    }

    let destination =
        u32::from_be_bytes(ctx.load(offset_of!(Ipv4Hdr, dst_addr))?);

    // (3)
    let action = if block_ip(destination) { 0 } else { 1 };

    let log_entry = PacketLog {
        ipv4_address: destination,
        action,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(action)
}

const ETH_P_IP: u32 = 8;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
