use anyhow::Result;
use clap::{crate_authors, crate_version, Parser};

mod pprint;

#[derive(Parser)]
#[command(
    version = crate_version!(),
    author = crate_authors!(),
)]
enum Command {
    /// Fetches the specified URL and pretty-prints the certificate.
    #[clap(name = "print")]
    PPrint {
        url: String,

        /// Specifies one or more encodings to accept.
        #[arg(long)]
        accept_encoding: Option<Vec<String>>,
    },
}

fn main() -> Result<()> {
    match Command::parse() {
        Command::PPrint {
            url,
            accept_encoding,
        } => pprint::pprint(url, accept_encoding),
    }
}

#[cfg(test)]
mod tests {
    use super::Command;
    use clap::CommandFactory;

    #[test]
    fn valid_command() {
        Command::command().debug_assert();
    }
}
