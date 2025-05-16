use clap::{Arg, Command};

/// Build and return the CLI parser
pub fn build_cli() -> Command {
    Command::new("zkSBOM")
        .version("1.0")
        .author("Tom Sorger <sorger@kth.se>")
        .about("A tool.")
        .arg(
            Arg::new("timing_analysis")
                .long("timing_analysis")
                .value_name("TIMING_ANALYSIS")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("timing_analysis_output")
                .long("timing_analysis_output")
                .value_name("TIMING_ANALYSIS_OUTPUT")
                .help("")
                .global(true),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a Proof")
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
                )
                .arg(
                    Arg::new("method")
                        .long("method")
                        .value_name("METHOD")
                        .help("Method for generating the ZKP (e.g., 'Merkle Tree', 'tbd.')")
                        .required(true),
                ),
        )
}
