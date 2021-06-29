use anyhow::Result;
use clap::{crate_authors, crate_version, Clap};

mod pprint;

#[derive(Clap)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
)]
enum Command {
    /// Fetches the specified URL and pretty-prints the certificate.
    #[clap(name = "print")]
    PPrint { url: String },
}

fn main() -> Result<()> {
    match Command::parse() {
        Command::PPrint { url } => pprint::pprint(url),
    }
}
