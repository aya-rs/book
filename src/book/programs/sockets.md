# Sockets

[Official eBPF program type description](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS)

## Program example

You can follow the
[basic XDP example](../start/development.md#starting-a-new-project)
to make a project structure.

E.g.: `cargo generate --name hello-sockops -d program_type=sock_ops https://github.com/aya-rs/aya-template`

Below is the eBPF part of the program (`hello-sockops-ebpf/src/main.rs`) commented:

```rust
#![no_std]
#![no_main]

use aya_ebpf::{EbpfContext, macros::sock_ops, programs::SockOpsContext};
use aya_log_ebpf::{info, warn};

enum SockOpsResult {
    // From the official docs:
    //   Regardless of the type of operation,
    //   the program should always return 1 on success.
    //   A negative integer indicate a operation is not supported.
    Ok = 1,
    #[allow(dead_code)]
    Err = 2, // Some other number to indicate error
}

// Cannot do `cargo add libc` due to no_std
// use libc::AF_INET;
const AF_INET: u32 = 2;

#[sock_ops]
pub fn socket_ops(ctx: SockOpsContext) -> u32 {
    try_socket_ops(ctx) as u32
}

fn try_socket_ops(ctx: SockOpsContext) -> SockOpsResult {
    // ctx.op() specifies the type of operation this eBPF program should perform.
    // So, sock_ops program will look like this most of the time:
    // ```
    // match ctx.op() {
    //     aya_ebpf::bindings::BPF_SOCK_OPS_NEEDS_ECN => { ... }
    //     ...
    // }
    // ```
    // The program just dumps information about captured INET socket operation
    info!(&ctx, "started..");
    if ctx.family() == AF_INET {
        let local_ipv4_addr = ctx.local_ip4();
        let local_port = ctx.local_port();
        let pid = ctx.pid();
        warn!(
            ctx,
            "PID {} | from {}:{} | op {}",
            pid,
            local_ipv4_addr,
            local_port,
            ctx.op()
        );
    }
    SockOpsResult::Ok
}

// Stub panic handler to please the compiler
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

The following userspace code loads the above program:

```rust
use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    let mut ebpf_sockops = aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/hello-sockops")))?;

    env_logger::init();
    let mut logger = match aya_log::EbpfLogger::init(&mut ebpf_sockops) {
        Err(e) => {
            log::warn!("failed to initialize eBPF logger: {e}");
            None
        }
        Ok(logger) => Some(logger),
    };

    let program_name = "socket_ops";
    let program: &mut aya::programs::SockOps = ebpf_sockops
        .program_mut(program_name)
        .expect(format!("no eBPF program named {program_name}").as_str())
        .try_into()?;
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
```

Try to start the program with `RUST_LOG=warn cargo run` and run `curl goo.gle`
in another terminal to see information on the new socket logged
by the eBPF program.
