use std::process;

use aya::{Btf, programs::Lsm};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // (1)
    let pid = process::id() as i32;
    info!("PID: {pid}");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::EbpfLoader::new().set_global("PID", &pid, true).load(
        aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lsm-nice")),
    )?;
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
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm =
        bpf.program_mut("task_setnice").unwrap().try_into()?;
    program.load("task_setnice", &btf)?;
    program.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
