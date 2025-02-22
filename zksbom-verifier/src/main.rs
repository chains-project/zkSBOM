use log::{debug, error, info, LevelFilter};
use std::str::FromStr;
pub mod config;
use config::load_config;
pub mod cli;
use cli::build_cli;
pub mod merkle;
use merkle::verify_merkle;

fn main() {
    init_logger();
    debug!("Logger initialized.");

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

fn parse_cli() {
    debug!("Parse cli...");
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("verify_merkle", sub_matches)) => {
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let proof_path = sub_matches.get_one::<String>("proof_path").unwrap();
            let is_valid = verify_merkle(commitment, proof_path);
            println!("Proof is valid: {}", is_valid);
        }
        _ => error!("No subcommand matched"),
    }
}
