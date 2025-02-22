use clap::{Arg, Command};

/// Build and return the CLI parser
pub fn build_cli() -> Command {
    Command::new("zkSBOM")
        .version("1.0")
        .author("Tom Sorger <sorger@kth.se>")
        .about("A tool.")
        .subcommand(
            Command::new("upload_sbom")
                .about("Upload or update an SBOM")
                .arg(
                    Arg::new("api-key")
                        .long("api-key")
                        .value_name("API_KEY")
                        .help("API key for authentication")
                        .required(true),
                )
                .arg(
                    Arg::new("sbom")
                        .long("sbom")
                        .value_name("FILE")
                        .help("Path to the SBOM file")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("get_commitment")
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
            Command::new("get_zkp_full")
                .about("Get a ZK proof")
                .arg(
                    Arg::new("api-key")
                        .long("api-key")
                        .value_name("API_KEY")
                        .help("API key for authentication")
                        .required(true),
                )
                .arg(
                    Arg::new("method")
                        .long("method")
                        .value_name("METHOD")
                        .help("Method for generating the ZKP (e.g., 'Merkle Tree', 'tbd.')")
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
                )
                .arg(
                    Arg::new("vulnerability")
                        .long("vulnerability")
                        .value_name("VULNERABILITY")
                        .help("Vulnerability to check")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("get_zkp")
                .about("Get a ZK proof")
                .arg(
                    Arg::new("api-key")
                        .long("api-key")
                        .value_name("API_KEY")
                        .help("API key for authentication")
                        .required(true),
                )
                .arg(
                    Arg::new("method")
                        .long("method")
                        .value_name("METHOD")
                        .help("Method for generating the ZKP (e.g., 'Merkle Tree', 'tbd.')")
                        .required(true),
                )
                .arg(
                    Arg::new("commitment")
                        .long("commitment")
                        .value_name("COMMITMENT")
                        .help("The commitment hash (required if method is 'commitment')"),
                )
                .arg(
                    Arg::new("vulnerability")
                        .long("vulnerability")
                        .value_name("VULNERABILITY")
                        .help("Vulnerability to check")
                        .required(true),
                ),
        )
}
