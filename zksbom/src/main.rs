use log::{debug, info, error, LevelFilter};
use std::str::FromStr;

pub mod config;
use config::load_config;

mod database{
    pub mod db_commitment;
    pub mod db_sbom;
    pub mod db_vulnerability;
}
use database::{
    db_commitment::{CommitmentDbEntry, init_db_commitment, insert_commitment, get_commitment, delete_db_commitment},
    db_sbom::{SbomDbEntry, init_db_sbom, insert_sbom, get_sbom, delete_db_sbom},
    db_vulnerability::{VulnerabilityDbEntry, init_db_vulnerability, insert_vulnerability, get_vulnerabilities, delete_db_vulnerability},
};

pub mod cli;
use cli::build_cli;

pub mod upload;
use upload::upload;


pub mod method{
    pub mod method_handler;
    pub mod merkle_tree;
}
use method::method_handler::{get_commitment as mh_get_commitment, get_zkp};


fn main() {
    init_logger();
    debug!("Logger initialized.");
    
    debug!("Initializing the databases...");
    init_dbs();

    debug!("Parse cli...");
    parse_cli();
}

fn init_logger() {
    let config = load_config().unwrap();
    let log_level = config.app.log_level;

    match LevelFilter::from_str(&log_level) {
        Ok(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or(&log_level));
            info!("Setting log level to '{}'", &log_level);
        }
        Err(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));
            error!("Invalid log level '{}' in config.toml. Using default 'warn'.", &log_level);
        }
    };
}

fn init_dbs() {
    // TODO: Remove delete
    // delete_db_commitment();
    // delete_db_sbom();
    // delete_db_vulnerability();

    init_db_commitment();
    init_db_sbom();
    init_db_vulnerability();
    // test_dbs();
}

fn parse_cli() {
    debug!("Parse cli...");
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("upload_sbom", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let sbom_path = sub_matches.get_one::<String>("sbom").unwrap();
            debug!("API Key: {}, SBOM Path: {}", api_key, sbom_path);
            upload(&api_key, &sbom_path);
        }
        Some(("get_commitment", sub_matches)) => {
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            debug!("Vendor: {}, Product: {}, Version: {}", vendor, product, version);
            let commitment = mh_get_commitment(&vendor, &product, &version);
            println!("Commitment: {}", commitment);
        }
        Some(("get_zkp", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let vulnerability = sub_matches.get_one::<String>("vulnerability").unwrap();
            debug!("API Key: {}, Method: {}, Commitment: {}, Vulnerability: {}", api_key, method, commitment, vulnerability);
            get_zkp(&api_key, &method, &commitment, &vulnerability);
        }
        Some(("get_zkp_full", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            let vulnerability = sub_matches.get_one::<String>("vulnerability").unwrap();
            debug!("API Key: {}, Method: {}, Vendor: {}, Product: {}, Version: {}, Vulnerability: {}", api_key, method, vendor, product, version, vulnerability);
            error!("Implement get_zkp");
        }
        _ => println!("No subcommand matched"),
    }
}

// TODO: Remove this test function
fn test_dbs() {
    // Test commitment database
    insert_commitment(CommitmentDbEntry {
        vendor: "vendor".to_string(),
        product: "product".to_string(),
        version: "version".to_string(),
        commitment: "this is a test commitment".to_string(),
    });
    let commitment = get_commitment("vendor".to_string(), "product".to_string(), "version".to_string());
    debug!("{:?}", commitment);

    // Test sbom database
    insert_sbom(SbomDbEntry {
        vendor: "vendor".to_string(),
        product: "product".to_string(),
        version: "version".to_string(),
        sbom: "this is a test sbom".to_string(),
    });
    let sbom = get_sbom("vendor".to_string(), "product".to_string(), "version".to_string());
    debug!("{:?}", sbom);

    // Test vulnerability database
    insert_vulnerability(VulnerabilityDbEntry {
        vulnerabilities: "vulnerabilities".to_string(),
        commitment: "commitment".to_string(),
    });
    let vulnerability = get_vulnerabilities("commitment".to_string());
    debug!("{:?}", vulnerability);
}
