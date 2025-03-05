use anyhow::{Context as _, Result};
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Codegen { output: std::path::PathBuf },
}

fn main() -> Result<()> {
    match Parser::parse() {
        Command::Codegen { output } => {
            let bindings = aya_tool::generate::generate(
                aya_tool::generate::InputFile::Btf(std::path::PathBuf::from(
                    "/sys/kernel/btf/vmlinux",
                )),
                &["iphdr"],
                &[],
            )
            .context("generate")?;
            std::fs::write(&output, &bindings).context("write")?;
        }
    }
    Ok(())
}
