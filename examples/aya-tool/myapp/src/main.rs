use aya::{Btf, programs::Lsm};
use log::info;
use std::sync::{Arc, Barrier};

fn main() {
    if let Err(e) = try_main() {
        eprintln!("error: {e:#}");
    }
}

fn try_main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Ebpf::load_file` instead.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/myapp"
    )))?;

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm =
        bpf.program_mut("task_alloc").unwrap().try_into()?;
    program.load("task_alloc", &btf)?;
    program.attach()?;

    let barrier = Arc::new(Barrier::new(2));

    {
        let barrier = barrier.clone();
        ctrlc::set_handler(move || {
            barrier.wait();
        })
        .expect("Error setting Ctrl-C handler");
    }

    info!("Waiting for Ctrl-C...");
    barrier.wait();
    info!("Exiting...");

    Ok(())
}
