use aya::{include_bytes_aligned, Ebpf};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use std::net;
use clap::Parser;
use tokio::{signal, task};

use myapp_common::PacketLog;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/myapp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp"
    ))?;
    // (1)
    let program: &mut Xdp = ebpf.program_mut("xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // (2)
    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        // (3)
        let mut buf = perf_array.open(cpu_id, None)?;

        // (4)
        task::spawn(async move {
            // (5)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // (6)
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    // (7)
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    // (8)
                    println!("LOG: SRC {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
