use clap::{Arg, Command};

/// Build and return the CLI parser
pub fn build_cli() -> Command {
    Command::new("zkSBOM")
        .version("1.0")
        .author("Tom Sorger <sorger@kth.se>")
        .about("A tool.")
        .subcommand(
            Command::new("verify_merkle")
                .about("Verify Merkle Inclusion Proof")
                .arg(
                    Arg::new("commitment")
                        .long("commitment")
                        .value_name("COMMITMENT")
                        .help("Commitment")
                        .required(true),
                )
                .arg(
                    Arg::new("proof_path")
                        .long("proof_path")
                        .value_name("PROOF_PATH")
                        .help("Path to the proof file")
                        .required(true),
                ),
        )
    }
