// ANCHOR: use
use aya::Bpf;
use aya::programs::{Xdp, XdpFlags};
use std::{
    convert::TryInto,
    env,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration
};
use structopt::StructOpt;
// ANCHOR_END: use

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

// ANCHOR: try_main
fn try_main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();
    let mut bpf = Bpf::load_file(&opt.path)?;
    let program: &mut Xdp = bpf.program_mut("xdp")?.try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Exiting...");

    Ok(())
}
// ANCHOR_END: try_main