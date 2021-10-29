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
// ANCHOR_END: use

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

// ANCHOR: try_main
fn try_main() -> Result<(), anyhow::Error> {
    let path = match env::args().nth(1) {
        Some(iface) => iface,
        None => panic!("not path provided"),
    };
    let iface = match env::args().nth(2) {
        Some(iface) => iface,
        None => "lo".to_string(),
    };
    let mut bpf = Bpf::load_file(&path)?;
    let probe: &mut Xdp = bpf.program_mut("xdp")?.try_into()?;
    probe.load()?;
    probe.attach(&iface, XdpFlags::default())?;

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