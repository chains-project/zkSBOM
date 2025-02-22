use clap::{Arg, Command};

/// Build and return the CLI parser
pub fn build_cli() -> Command {
    Command::new("ZK-SBOM Tool")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("A tool for managing SBOMs and ZK proofs")
        .subcommand(
            Command::new("upload")
                .about("Upload or update an SBOM")
                .arg(
                    Arg::new("sbom")
                        .long("sbom")
                        .value_name("FILE")
                        .help("Path to the SBOM file")
                        .required(true),
                )
                .arg(
                    Arg::new("vendor")
                        .long("vendor")
                        .value_name("VENDOR")
                        .help("Name of the vendor")
                        .required(true),
                )
                .arg(
                    Arg::new("product")
                        .long("product")
                        .value_name("PRODUCT")
                        .help("Name of the product")
                        .required(true),
                )
                .arg(
                    Arg::new("version")
                        .long("version")
                        .value_name("VERSION")
                        .help("Version of the product")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("get-commitment")
                .about("Get the commitment for a product and version")
                .arg(
                    Arg::new("vendor")
                        .long("vendor")
                        .value_name("VENDOR")
                        .help("Name of the vendor")
                        .required(true),
                )
                .arg(
                    Arg::new("product")
                        .long("product")
                        .value_name("PRODUCT")
                        .help("Name of the product")
                        .required(true),
                )
                .arg(
                    Arg::new("version")
                        .long("version")
                        .value_name("VERSION")
                        .help("Version of the product")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("get-zk-proof")
                .about("Get a ZK proof for a given commitment and vulnerability")
                .arg(
                    Arg::new("api-key")
                        .long("api-key")
                        .value_name("API_KEY")
                        .help("API key for authentication")
                        .required(true),
                )
                .arg(
                    Arg::new("commitment")
                        .long("commitment")
                        .value_name("COMMITMENT")
                        .help("The commitment hash")
                        .required(true),
                )
                .arg(
                    Arg::new("vulnerability")
                        .long("vulnerability")
                        .value_name("VULNERABILITY")
                        .help("The vulnerability identifier")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify a ZK proof against a commitment")
                // .arg(
                //     Arg::new("commitment")
                //         .long("commitment")
                //         .value_name("COMMITMENT")
                //         .help("The commitment hash")
                //         .required(true),
                // )
                .arg(
                    Arg::new("zkproof")
                        .long("zkproof")
                        .value_name("ZKPROOF")
                        .help("The ZK proof to verify")
                        .required(true),
                ),
        )
}
