use crate::cli::build_cli;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub db_commitment: DatabaseConfig,
    pub db_sbom: DatabaseConfig,
    pub db_dependency: DatabaseConfig,
    pub db_vulnerabilities: DatabaseConfig,
    pub db_ozks: DatabaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub output: String,
    pub clean_init_dbs: bool,
    pub check_dependencies: bool,
    pub check_dependencies_output: String,
    pub github_token: String,
    pub timing_analysis: bool,
    pub timing_analysis_output: String,
    pub salt: bool,
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
    if let Some(db_dependency_path) = matches.get_one::<String>("db_dependency_path") {
        config.db_dependency.path = db_dependency_path.clone();
    }
    if let Some(db_vulnerabilities_path) = matches.get_one::<String>("db_vulnerabilities_path") {
        config.db_vulnerabilities.path = db_vulnerabilities_path.clone();
    }
    if let Some(db_ozks_path) = matches.get_one::<String>("db_ozks_path") {
        config.db_ozks.path = db_ozks_path.clone();
    }
    if let Some(timing_analysis) = matches.get_one::<String>("timing_analysis") {
        config.app.timing_analysis = timing_analysis.parse::<bool>()?;
    }
    if let Some(timing_analysis_output) = matches.get_one::<String>("timing_analysis_output") {
        config.app.timing_analysis_output = timing_analysis_output.clone();
    }
    if let Some(salt) = matches.get_one::<String>("salt") {
        config.app.salt = salt.parse::<bool>()?;
    }

    Ok(config)
}
