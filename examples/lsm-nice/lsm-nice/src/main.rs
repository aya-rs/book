use std::process;

use aya::{include_bytes_aligned, programs::Lsm, EbpfLoader, Btf};
use log::info;
use simplelog::{
    ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode,
};
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

    // (1)
    let pid = process::id() as i32;
    info!("PID: {}", pid);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    // (2)
    let mut ebpf = EbpfLoader::new().set_global("PID", &pid).load(
        include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/lsm-nice"
        ),
    )?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm =
        ebpf.program_mut("task_setnice").unwrap().try_into()?;
    program.load("task_setnice", &btf)?;
    program.attach()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
