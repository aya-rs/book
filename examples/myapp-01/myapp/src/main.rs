// ANCHOR: all
// ANCHOR: use
use aya::{include_bytes_aligned, Bpf};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::signal;
// ANCHOR_END: use

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

// ANCHOR: tokiomain
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp"
    ))?;
    let program: &mut Xdp = bpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
// ANCHOR_END: tokiomain

