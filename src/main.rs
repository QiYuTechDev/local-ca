mod cli;
mod gen;

use structopt::StructOpt;

use cli::Cli;

fn main() {
    let cli: Cli = Cli::from_args();

    cli.run();
}
