use clap::{Arg, Command};

/// Build and return the CLI parser
pub fn build_cli() -> Command {
    Command::new("zkSBOM")
        .version("1.0")
        .author("Tom Sorger <sorger@kth.se>")
        .about("A tool.")
        .arg(
            Arg::new("log_level")
                .long("log_level")
                .value_name("LOG_LEVEL")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("OUTPUT")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("clean_init_dbs")
                .long("clean_init_dbs")
                .value_name("CLEAN_INIT_DBS")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("check_dependencies")
                .long("check_dependencies")
                .value_name("CHECK_DEPENDENCIES")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("check_dependencies_output")
                .long("check_dependencies_output")
                .value_name("CHECK_DEPENDENCIES_OUTPUT")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("db_commitment_path")
                .long("db_commitment_path")
                .value_name("DB_COMMITMENT_PATH")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("db_dependency_path")
                .long("db_dependency_path")
                .value_name("DB_DEPENDENCY_PATH")
                .help("")
                .global(true),
        )
        .arg(
            Arg::new("db_vulnerabilities_path")
                .long("db_vulnerabilities_path")
                .value_name("DB_VULNERABILITIES_PATH")
                .help("")
                .global(true),
        )
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
                )
                .arg(
                    Arg::new("method")
                        .long("method")
                        .value_name("METHOD")
                        .help("Method for generating the ZKP (e.g., 'Merkle Tree', 'tbd.')")
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
        .subcommand(
            Command::new("map_vulnerabilities").about("Map vulnerabilities to dependencies"),
        )
}
