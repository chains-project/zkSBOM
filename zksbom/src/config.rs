use serde::Deserialize;
use std::fs;

use crate::cli::build_cli;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub db_commitment: DatabaseConfig,
    pub db_sbom: DatabaseConfig,
    pub db_dependency: DatabaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub output: String,
    pub clean_init_dbs: bool,
    pub check_dependencies: bool,
    pub check_dependencies_output: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = "./config/config.toml";
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;

    let matches = build_cli().get_matches();

    // Override with CLI arguments if provided
    if let Some(log_level) = matches.get_one::<String>("log_level") {
        config.app.log_level = log_level.clone();
    }
    if let Some(output) = matches.get_one::<String>("output") {
        config.app.output = output.clone();
    }
    if let Some(clean_init_dbs) = matches.get_one::<String>("clean_init_dbs") {
        config.app.clean_init_dbs = clean_init_dbs.parse::<bool>()?;
    }
    if let Some(check_dependencies) = matches.get_one::<String>("check_dependencies") {
        config.app.check_dependencies = check_dependencies.parse::<bool>()?;
    }
    if let Some(db_commitment_path) = matches.get_one::<String>("db_commitment_path") {
        config.db_commitment.path = db_commitment_path.clone();
    }
    if let Some(db_sbom_path) = matches.get_one::<String>("db_sbom_path") {
        config.db_sbom.path = db_sbom_path.clone();
    }
    if let Some(db_dependency_path) = matches.get_one::<String>("db_dependency_path") {
        config.db_dependency.path = db_dependency_path.clone();
    }

    Ok(config)
}
