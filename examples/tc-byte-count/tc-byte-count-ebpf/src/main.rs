#![no_std]
#![no_main]

use core::ops::Add;

use aya_ebpf::{
    bindings::{BPF_ANY, TC_ACT_PIPE},
    macros::{classifier, map},
    maps::LruPerCpuHashMap,
    programs::TcContext,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

/// An LRU map that will hold information about bytes transmited.
/// The map is keyed on remote port. Values in this map are per-cpu,
/// meaning no locking is required to ensure consistent updates.
/// Values are evicted only when space is needed in the map.
#[map]
static EGRESS: LruPerCpuHashMap<u16, u64> = LruPerCpuHashMap::with_max_entries(1024, 0);

/// An LRU map that will hold information about bytes received.
/// The map is keyed on remote port. Values in this map are per-cpu,
/// meaning no locking is required to ensure consistent updates.
/// Values are evicted only when space is needed in the map.
#[map]
static INGRESS: LruPerCpuHashMap<u16, u64> = LruPerCpuHashMap::with_max_entries(1024, 0);

/// Entry point for our TrafficControl "EGRESS" eBPF attachment point.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let _res = try_tc_egress(ctx);

    //Always allow the packet to continue to its intended destination
    TC_ACT_PIPE
}

/// Entry point for our TrafficControl "INGRESS" eBPF attachment point.
#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let _res = try_tc_ingress(ctx);

    //Always allow the packet to continue to its intended destination
    TC_ACT_PIPE
}

/// In order to reduce the total memory and cpu resource expended in
/// producing this telemetry, we collapse remote port ranges that are unlikely
/// to be of interest. For example, interesting ports include:
/// mysql: 3306 sqlserver: 1433 postgres: 5432, oracle: 1521, ephemeral: 32768 - 65535
#[inline(always)]
fn map_port(port: u16) -> u16 {
    if (32768..=65535).contains(&port) {
        //ephemeral range, we can collapse these entirely
        0
    } else {
        // anything else, lets track it specifically
        port
    }
}

/// Handles accounting of EGRESS packets, storing telemetry by map_port(REMOTE port)
/// There is some duplicate code between this method and try_tc_ingress. This was intentional
/// as the effort to de-duplicate wasn't worth it given its only a handful of duplicate lines
#[inline(always)]
fn try_tc_egress(ctx: TcContext) -> Result<(), ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // We are using match instead of simple if because the eBPF verifier doesn't seem to like ether_type used
    // directly in an if without a stack variable copy. I think this is because EthHdr is a c-style "packed"
    // struct that is memory aligned. Still Day-1 for rust and eBPF I guess
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            // Since IPv6 adoption is low, we make a simplifying assumption that we can monitor only IPv6
        }
        _ => return Ok(()),
    }

    //Grab the IP Header so we can read the protocol and size of packet.
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Tcp {
        return Ok(());
    }

    //Calculate the offset of the TCP Header. The vast majority of the time
    //the IP header is a fixed 20 bytes but.. its possible to occasionally
    //have IP Options set that change the header size. So this handles that to
    //avoid blowing out the telemetry by reading random data instead of real ports
    let offset = if ipv4hdr.ihl() != 5 {
        EthHdr::LEN + (ipv4hdr.ihl() * 4) as usize
    } else {
        EthHdr::LEN + Ipv4Hdr::LEN
    };

    //Grab the TCP Header so we can read the remote port.
    let tcphdr: TcpHdr = ctx.load(offset).map_err(|_| ())?;
    let dst_port = map_port(u16::from_be(tcphdr.dest));
    let len = u16::from_be(ipv4hdr.tot_len);

    //Grab an existing value for this port (if present) and add the size of this packet.
    //No locking is needed since this is a per-cpu map.
    let val = unsafe {
        match EGRESS.get(&dst_port) {
            Some(val) => (len as u64).add(val),
            None => len as u64,
        }
    };

    //Update the map with the new value. No locking is needed since this is a per-cpu map.
    let _res = EGRESS.insert(&dst_port, &val, BPF_ANY.into());

    Ok(())
}

/// Handles accounting of INGRESS packets, storing telemetry by map_port(REMOTE port)
/// There is some duplicate code between this method and try_tc_ingress. This was intentional
/// as the effort to de-duplicate wasn't worth it given its only a handful of duplicate lines
#[inline(always)]
fn try_tc_ingress(ctx: TcContext) -> Result<(), ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    // We are using match instead of simple if because the eBPF verifier doesn't seem to like ether_type used
    // directly in an if without a stack variable copy. I think this is because EthHdr is a c-style "packed"
    // struct that is memory aligned. Still Day-1 for rust and eBPF I guess
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            // Since IPv6 adoption is low, we make a simplifying assumption that we can monitor only IPv6
        }
        _ => return Ok(()),
    }

    //Grab the IP Header so we can read the protocol and size of packet.
    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4hdr.proto != IpProto::Tcp {
        return Ok(());
    }

    match ipv4hdr.proto {
        IpProto::Tcp => {}
        _ => return Ok(()),
    }

    //Calculate the offset of the TCP Header. The vast majority of the time
    //the IP header is a fixed 20 bytes but.. its possible to occasionally
    //have IP Options set that change the header size. So this handles that to
    //avoid blowing out the telemetry by reading random data instead of real ports
    let offset = if ipv4hdr.ihl() != 5 {
        EthHdr::LEN + (ipv4hdr.ihl() * 4) as usize
    } else {
        EthHdr::LEN + Ipv4Hdr::LEN
    };

    //Grab the TCP Header so we can read the remote port.
    let tcphdr: TcpHdr = ctx.load(offset).map_err(|_| ())?;
    let src_port = map_port(u16::from_be(tcphdr.source));

    //Grab the size of the packet (excluding the ethernet header, slightly inaccurate but its a rounding error)
    let len = u16::from_be(ipv4hdr.tot_len);

    //Grab an existing value for this port (if present) and add the size of this packet.
    //No locking is needed since this is a per-cpu map.
    let val = unsafe {
        match INGRESS.get(&src_port) {
            Some(val) => (len as u64).add(val),
            None => len as u64,
        }
    };

    //Update the map with the new value. No locking is needed since this is a per-cpu map.
    let _res = INGRESS.insert(&src_port, &val, BPF_ANY.into());

    Ok(())
}

/// This is never used, its something that is required to satisfy the eBPF verifier since AYA and Rust support
/// are still pretty new.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
