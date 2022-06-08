use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use std::{env, fs, net};
use tokio::{signal, task};

use myapp_common::PacketLog;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => panic!("no path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "eth0".to_string(),
    };

    let data = fs::read(path)?;
    let mut bpf = Bpf::load(&data)?;

    let probe: &mut Xdp = bpf.program_mut("xdp").unwrap().try_into()?;
    probe.load()?;
    probe.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // (1)
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        // (2)
        let mut buf = perf_array.open(cpu_id, None)?;

        // (3)
        task::spawn(async move {
            // (4)
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // (5)
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    // (6)
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    // (7)
                    println!("LOG: SRC {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
