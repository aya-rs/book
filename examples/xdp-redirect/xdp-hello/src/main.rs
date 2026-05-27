use anyhow::Context;
use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, log, warn};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;
use xsk_rs::config::{
    LibxdpFlags, SocketConfig, SocketConfigBuilder, UmemConfig,
};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

struct SocketResources {
    pub frame_cnt: u32,
    pub umem: Umem,
    pub tx_q: TxQueue,
    pub rx_q: RxQueue,
    pub fill_q: FillQueue,
    pub comp_q: CompQueue,
}

fn setup_sockets(
    iface: &String,
    queue_cnt: u32,
) -> anyhow::Result<Vec<SocketResources>> {
    let frame_cnt = 32;
    let mut res = Vec::new();
    let socket_config = SocketConfigBuilder::new()
        // ask libxdp to not attach a default xdp program
        .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
        .build();
    for queue_id in 0..queue_cnt {
        let (umem, frame_descs) = Umem::new(
            UmemConfig::default(),
            frame_cnt.try_into().unwrap(),
            false,
        )
        .context("failed to create UMEM")?;

        let (tx_q, rx_q, fq_and_cq) = unsafe {
            Socket::new(socket_config, &umem, &iface.parse().unwrap(), queue_id)
        }
        .context("Unable to open a socket")?;

        let (mut fill_q, comp_q) =
            fq_and_cq.context("Unable to create Fill and Completion queues")?;

        unsafe { fill_q.produce(&frame_descs) };

        res.push(SocketResources {
            frame_cnt,
            umem,
            tx_q,
            rx_q,
            fill_q,
            comp_q,
        });
    }

    Ok(res)
}

fn run_queue_loop(
    mut socket: SocketResources,
    cancellation: &AtomicBool,
) -> anyhow::Result<()> {
    let mut descs = vec![FrameDesc::default(); socket.frame_cnt as usize];
    while !cancellation.load(Ordering::Relaxed) {
        let packet_cnt =
            unsafe { socket.rx_q.poll_and_consume(&mut descs, 100)? };

        for desc in &descs[..packet_cnt] {
            let mut data = unsafe { socket.umem.data(&desc) }.contents();

            info!(
                "Received packet, {} bytes: {:02x?}",
                data.len(),
                &data[..data.len().min(64)]
            );
        }

        unsafe { socket.fill_q.produce(&descs[..packet_cnt]) };
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-hello"
    )))?;
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = bpf.program_mut("xdp_ping").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    // Create AF_XDP sockets
    let queue_cnt: u32 = 8;
    let socket_resources = setup_sockets(&opt.iface, queue_cnt)?;

    // Create sockets map
    let mut sockets_map: XskMap<_> = XskMap::try_from(
        bpf.map_mut("SOCKS").context("Unable to load sockets map")?,
    )?;

    // Load RX queue descriptors into the sockets map
    for queue_idx in 0..queue_cnt {
        sockets_map.set(
            queue_idx,
            socket_resources[queue_idx as usize].rx_q.fd().as_raw_fd(),
            0,
        )?;
    }
    let cancellation = Arc::new(AtomicBool::new(false));

    tokio::spawn({
        let cancellation = cancellation.clone();
        async move {
            info!("Waiting for Ctrl-C...");
            let _ = signal::ctrl_c().await;
            cancellation.store(true, Ordering::Relaxed);
            info!("Exiting...");
        }
    });

    std::thread::scope(|s| {
        for socket in socket_resources.into_iter() {
            s.spawn(|| {
                run_queue_loop(socket, &cancellation);
            });
        }
    });

    Ok(())
}
