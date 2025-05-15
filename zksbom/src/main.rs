pub mod check_dependencies_crates_io;
pub mod cli;
pub mod config;
mod database {
    pub mod db_commitment;
    pub mod db_dependency;
    pub mod db_vulnerabilities;
}
pub mod github_advisory_database_mapping;
pub mod hasher;
pub mod map_dependencies_vulnerabilities;
pub mod method {
    pub mod merkle_patricia_trie;
    pub mod merkle_tree;
    pub mod method_handler;
    pub mod sparse_merkle_tree;
}
pub mod upload;

use cli::build_cli;
use config::load_config;
use database::{
    db_commitment::{delete_db_commitment, init_db_commitment},
    db_dependency::{delete_db_dependency, init_db_dependency},
    db_vulnerabilities::{delete_db_vulnerabilities, init_db_vulnerabilities},
};
use log::{debug, error, LevelFilter};
use method::method_handler::{get_commitment as mh_get_commitment, get_zkp, get_zkp_full};
use std::str::FromStr;
use upload::upload;

fn main() {
    init_logger();
    let config = load_config().unwrap();
    let is_clean_init = config.app.clean_init_dbs;
    delete_dbs(is_clean_init);
    init_dbs();
    parse_cli();
}

fn init_logger() {
    let config = load_config().unwrap();
    let log_level = config.app.log_level;

    match LevelFilter::from_str(&log_level) {
        Ok(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or(&log_level));
            debug!("Setting log level to '{}'", &log_level);
        }
        Err(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));
            error!(
                "Invalid log level '{}' in config.toml. Using default 'warn'.",
                &log_level
            );
        }
    };
    debug!("Logger initialized.");
}

fn init_dbs() {
    debug!("Initializing the databases...");
    init_db_commitment();
    init_db_dependency();
    init_db_vulnerabilities();
}

fn delete_dbs(is_clean_init: bool) {
    if is_clean_init {
        delete_db_commitment();
        delete_db_dependency();
        delete_db_vulnerabilities();
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
            let method = sub_matches.get_one::<String>("method").unwrap();
            debug!(
                "Vendor: {}, Product: {}, Version: {}, Method: {}",
                vendor, product, version, method
            );
            let commitment = mh_get_commitment(&vendor, &product, &version, &method);
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
        Some(("map_vulnerabilities", sub_matches)) => {
            error!("Mapping vulnerabilities is not implemented yet.");
        }
        _ => {
            error!("No valid subcommand provided.");
        }
    }
}
