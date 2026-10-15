use anyhow::Context as _;
use log::warn;

fn main() -> anyhow::Result<()> {
    let mut ebpf_sockops = aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/hello-sockops")
    ))?;

    env_logger::init();
    let mut logger = match aya_log::EbpfLogger::init(&mut ebpf_sockops) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
            None
        }
        Ok(logger) => Some(logger),
    };

    const PROGRAM_NAME: &str = "socket_ops";
    let program: &mut aya::programs::SockOps =
        ebpf_sockops.program_mut(PROGRAM_NAME).unwrap().try_into()?;
    program.load()?;
    let root_cg_file = std::fs::File::open("/sys/fs/cgroup")?;
    program
        .attach(root_cg_file, aya::programs::CgroupAttachMode::Single)
        .context("failed to attach the SockOps to root cgroup")?;

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(logger) = logger.as_mut() {
            logger.flush();
        }
    }
}
