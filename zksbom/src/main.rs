use log::{debug, error, info, LevelFilter};
use std::str::FromStr;
use zksbom::cli::build_cli;
use zksbom::config::load_config;
use zksbom::database::{
    db_commitment::{delete_db_commitment, init_db_commitment},
    db_dependency::{delete_db_dependency, init_db_dependency},
};
use zksbom::method::method_handler::{create_proof, create_proof_no_commitment, get_commitment};
use zksbom::upload::upload;

fn main() {
    let config = load_config().unwrap();
    init_logger(&config);
    let is_clean_init = config.app.clean_init_dbs;
    delete_dbs(is_clean_init, &config);
    init_dbs(&config);
    parse_cli(&config);
}

fn init_logger(config: &zksbom::config::Config) {
    let log_level = &config.app.log_level;

    match LevelFilter::from_str(log_level) {
        Ok(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or(log_level));
            debug!("Setting log level to '{}'", log_level);
        }
        Err(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));
            error!(
                "Invalid log level '{}' in config.toml. Using default 'warn'.",
                log_level
            );
        }
    };
    debug!("Logger initialized.");
}

fn init_dbs(config: &zksbom::config::Config) {
    debug!("Initializing the databases...");
    init_db_commitment(config);
    init_db_dependency(config);
}

fn delete_dbs(is_clean_init: bool, config: &zksbom::config::Config) {
    if is_clean_init {
        delete_db_commitment(config);
        delete_db_dependency(config);
        // Also delete the oZKS SQLite database
        let ozks_db_path = &config.db_ozks.path;
        if std::path::Path::new(ozks_db_path).exists() {
            if let Err(e) = std::fs::remove_file(ozks_db_path) {
                log::error!("Error deleting oZKS database: {}", e);
            } else {
                log::debug!("Deleted oZKS database at: {}", ozks_db_path);
            }
        }
    }
}

fn parse_cli(config: &zksbom::config::Config) {
    debug!("Parse cli...");
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("upload_sbom", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let sbom_path = sub_matches.get_one::<String>("sbom").unwrap();
            debug!("API Key: {}, SBOM Path: {}", api_key, sbom_path);
            upload(&api_key, &sbom_path, config);
            info!("Upload SBOM completed successfully.");
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
            let commitment = get_commitment(&vendor, &product, &version, &method, config);
            println!("Commitment: {}", commitment);
        }
        Some(("create_proof", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let check = sub_matches.get_one::<String>("check").unwrap();
            debug!(
                "API Key: {}, Method: {}, Commitment: {}, Check: {}",
                api_key, method, commitment, check
            );
            create_proof(&api_key, &method, &commitment, &check, config);
        }
        Some(("create_proof_no_commitment", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            let check = sub_matches.get_one::<String>("check").unwrap();
            debug!(
                "API Key: {}, Method: {}, Vendor: {}, Product: {}, Version: {}, Check: {}",
                api_key, method, vendor, product, version, check
            );
            create_proof_no_commitment(
                &api_key, &method, &vendor, &product, &version, &check, config,
            );
        }
        _ => {
            error!("No valid subcommand provided.");
        }
    }
}
