// ANCHOR: all
use std::process;

use aya::{include_bytes_aligned, BpfLoader};
use aya::{programs::Lsm, Btf};
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // ANCHOR: pid
    let pid = process::id() as i32;
    info!("PID: {}", pid);
    // ANCHOR_END: pid

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // ANCHOR: load
    let mut bpf = BpfLoader::new().set_global("PID", &pid).load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lsm-nice"
    ))?;
    // ANCHOR_END: load
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("task_setnice").unwrap().try_into()?;
    program.load("task_setnice", &btf)?;
    program.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
// ANCHOR_END: all
