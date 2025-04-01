use anyhow::{anyhow, Context as _};
use aya_build::{cargo_metadata, Toolchain};

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new()
            .no_deps()
            .exec()
            .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "xdp-drop-ebpf")
        .ok_or_else(|| anyhow!("xdp-drop-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
