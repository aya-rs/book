use std::{path::PathBuf, process::Command};

use structopt::StructOpt;

#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    BpfEl,
    BpfEb,
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

#[derive(StructOpt)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[structopt(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// Build profile for eBPF programs
    #[structopt(default_value = "release", long)]
    pub profile: String,
}

pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("lsm-nice-ebpf");
    let target = format!("--target={}", opts.target);
    let args = vec![
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
        "--profile",
        opts.profile.as_str(),
    ];

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(&dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
