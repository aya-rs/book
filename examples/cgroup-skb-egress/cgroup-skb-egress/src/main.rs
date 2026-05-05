use std::{mem::MaybeUninit, net::Ipv4Addr};

use aya::{
    maps::{
        HashMap,
        perf::{PerfEvent, PerfEventArray},
    },
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
    util::online_cpus,
};
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};

use cgroup_skb_egress_common::PacketLog;

// TODO(https://github.com/rust-lang/rust/issues/93092): replace with `MaybeUninit::as_bytes_mut`
// once stable.
fn as_bytes_mut<T>(slot: &mut MaybeUninit<T>) -> &mut [MaybeUninit<u8>] {
    // SAFETY: MaybeUninit<u8> imposes no validity invariants on its memory.
    unsafe {
        std::slice::from_raw_parts_mut(
            slot.as_mut_ptr().cast::<MaybeUninit<u8>>(),
            size_of::<T>(),
        )
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cgroup-skb-egress"
    )))?;
    let program: &mut CgroupSkb =
        bpf.program_mut("cgroup_skb_egress").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    // (1)
    program.load()?;
    // (2)
    program.attach(
        cgroup,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::Single,
    )?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    // (3)
    blocklist.insert(block_addr, 0, 0)?;

    let mut perf_array =
        PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let buf = perf_array.open(cpu_id, None)?;
        let mut buf = tokio::io::unix::AsyncFd::with_interest(
            buf,
            tokio::io::Interest::READABLE,
        )?;

        task::spawn(async move {
            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                guard.get_inner_mut().for_each(|event| match event {
                    PerfEvent::Sample { head, tail } => {
                        // Samples can straddle the ring's wrap boundary; copy a contiguous window.
                        let mut data = MaybeUninit::<PacketLog>::uninit();
                        let bytes = as_bytes_mut(&mut data);
                        let head_len = head.len().min(bytes.len());
                        let dst = bytes.as_mut_ptr().cast::<u8>();
                        // SAFETY: source and destination are non-overlapping, and the writes
                        // cover all of `bytes`; PacketLog is Pod so any byte pattern is valid.
                        let data = unsafe {
                            std::ptr::copy_nonoverlapping(
                                head.as_ptr(),
                                dst,
                                head_len,
                            );
                            std::ptr::copy_nonoverlapping(
                                tail.as_ptr(),
                                dst.add(head_len),
                                bytes.len() - head_len,
                            );
                            data.assume_init()
                        };
                        let src_addr = Ipv4Addr::from(data.ipv4_address);
                        info!("LOG: DST {}, ACTION {}", src_addr, data.action);
                    }
                    PerfEvent::Lost { count } => {
                        warn!("dropped {count} samples")
                    }
                });
                guard.clear_ready();
            }
        });
    }

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
