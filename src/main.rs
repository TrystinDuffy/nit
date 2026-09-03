use clap::Parser;
use git_vault::{cli::Cli, runtime};

fn main() {
    match runtime::run(Cli::parse()) {
        Ok(outcome) => {
            let code = outcome.exit_code();
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(error) => {
            eprintln!("git-vault: {error:#}");
            std::process::exit(1);
        }
    }
}
