use std::process;

use aya::{include_bytes_aligned, programs::Lsm, BpfLoader, Btf};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // (1)
    let pid = process::id() as i32;
    info!("PID: {}", pid);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new().set_global("PID", &pid, true).load(
        include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/lsm-nice"
        ),
    )?;

    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new().set_global("PID", &pid, true).load(
        include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/lsm-nice"
        ),
    )?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
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
