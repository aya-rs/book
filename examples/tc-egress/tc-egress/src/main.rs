use std::net::Ipv4Addr;

use aya::{
    maps::HashMap,
    programs::{SchedClassifier, TcAttachType, tc},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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
        "/tc-egress"
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
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier =
        bpf.program_mut("tc_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    // (1)
    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    // (2)
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();

    // (3)
    blocklist.insert(block_addr, 0, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
