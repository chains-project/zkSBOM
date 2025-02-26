use log::{debug, error, info, LevelFilter};
use std::str::FromStr;

pub mod config;
use config::load_config;

mod database {
    pub mod db_commitment;
    pub mod db_sbom;
    pub mod db_vulnerability;
}
use database::{
    db_commitment::{delete_db_commitment, init_db_commitment},
    db_sbom::{delete_db_sbom, init_db_sbom},
    db_vulnerability::{delete_db_vulnerability, init_db_vulnerability},
};

pub mod cli;
use cli::build_cli;

pub mod upload;
use upload::upload;

pub mod method {
    pub mod merkle_tree;
    pub mod method_handler;
}
use method::method_handler::{get_commitment as mh_get_commitment, get_zkp, get_zkp_full};

fn main() {
    init_logger();
    debug!("Logger initialized.");

    let config = load_config().unwrap();
    let is_clean_init = config.app.clean_init_dbs;
    delete_dbs(is_clean_init);

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
            error!(
                "Invalid log level '{}' in config.toml. Using default 'warn'.",
                &log_level
            );
        }
    };
}

fn init_dbs() {
    init_db_commitment();
    init_db_sbom();
    init_db_vulnerability();
}

// TODO: Delete function
fn delete_dbs(is_clean_init: bool) {
    if is_clean_init {
        delete_db_commitment();
        delete_db_sbom();
        delete_db_vulnerability();
    }
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
            debug!(
                "Vendor: {}, Product: {}, Version: {}",
                vendor, product, version
            );
            let commitment = mh_get_commitment(&vendor, &product, &version);
            println!("Commitment: {}", commitment);
        }
        Some(("get_zkp", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let vulnerability = sub_matches.get_one::<String>("vulnerability").unwrap();
            debug!(
                "API Key: {}, Method: {}, Commitment: {}, Vulnerability: {}",
                api_key, method, commitment, vulnerability
            );
            get_zkp(&api_key, &method, &commitment, &vulnerability);
        }
        Some(("get_zkp_full", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            let vulnerability = sub_matches.get_one::<String>("vulnerability").unwrap();
            debug!(
                "API Key: {}, Method: {}, Vendor: {}, Product: {}, Version: {}, Vulnerability: {}",
                api_key, method, vendor, product, version, vulnerability
            );
            get_zkp_full(
                &api_key,
                &method,
                &vendor,
                &product,
                &version,
                &vulnerability,
            );
        }
        _ => error!("No subcommand matched"),
    }
}
