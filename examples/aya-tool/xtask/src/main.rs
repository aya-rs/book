mod build_ebpf;
mod run;

use log::error;

use std::process::exit;

use structopt::StructOpt;
#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Run(run::Options),
}

fn main() {
    env_logger::init();
    let opts = Options::from_args();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        error!("{:#}", e);
        exit(1);
    }
}
