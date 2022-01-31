use std::{os::unix::process::CommandExt, process::Command};

use anyhow::Context as _;
use structopt::StructOpt;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

#[derive(StructOpt)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[structopt(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build profile for userspace program
    #[structopt(default_value = "dev", long)]
    pub profile: String,
    /// The command used to wrap your application
    #[structopt(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// Arguments to pass to your application
    #[structopt(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build the project
fn build(opts: &Options) -> Result<(), anyhow::Error> {
    let args = vec!["build", "--profile", opts.profile.as_str()];
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // build our ebpf program followed by our application
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        profile: opts.profile.clone(),
    })
    .context("Error while building eBPF program")?;
    build(&opts).context("Error while building userspace application")?;

    let target_dir = match opts.profile.as_str() {
        "dev" | "test" => "debug",
        "bench" | "release" => "release",
        _ => opts.profile.as_str(),
    };
    let bin_path = format!("target/{}/myapp", target_dir);

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // spawn the command
    let err = Command::new(args.get(0).expect("No first argument"))
        .args(args.iter().skip(1))
        .exec();

    // we shouldn't get here unless the command failed to spawn
    Err(anyhow::Error::from(err).context(format!("Failed to run `{}`", args.join(" "))))
}
