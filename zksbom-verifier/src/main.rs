pub mod cli;
pub mod config;
pub mod hasher;
pub mod method {
    pub mod merkle_patricia_trie;
    pub mod merkle_tree;
    pub mod method_handler;
    pub mod sparse_merkle_tree;
    pub mod ozks;
}

use cli::build_cli;
use config::load_config;
use log::{debug, error, LevelFilter};
use method::method_handler::verify;
use std::str::FromStr;

fn main() {
    init_logger();
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

fn parse_cli() {
    debug!("Parse cli...");
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("verify", sub_matches)) => {
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let proof_path = sub_matches.get_one::<String>("proof_path").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            debug!(
                "Commitment: {}, Proof Path: {}, Method: {}",
                commitment, proof_path, method
            );

            let is_valid = verify(commitment, proof_path, &method);
            println!("Proof is valid: {}", is_valid);
        }
        _ => error!("No subcommand matched"),
    }
}
