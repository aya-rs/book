use aya::{include_bytes_aligned, programs::Lsm, Ebpf, Btf};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use structopt::StructOpt;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {}

fn try_main() -> Result<(), anyhow::Error> {
    // command-line options a currently unused
    let _opt = Opt::from_args();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp"
    ))?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm =
        bpf.program_mut("task_alloc").unwrap().try_into()?;
    program.load("task_alloc", &btf)?;
    program.attach()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500))
    }
    println!("Exiting...");

    Ok(())
}
