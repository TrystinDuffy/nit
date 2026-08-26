use clap::Parser;
use git_vault::{cli::Cli, runtime};

fn main() {
    if let Err(error) = runtime::run(Cli::parse()) {
        eprintln!("git-vault: {error:#}");
        std::process::exit(1);
    }
}
