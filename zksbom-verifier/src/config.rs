use crate::cli::build_cli;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub timing_analysis: bool,
    pub timing_analysis_output: String,
}

/// Load config from file only (without CLI argument parsing)
/// Useful for tests and non-CLI use cases
pub fn load_config_from_file(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = "./config/config.toml";
    let mut config = load_config_from_file(path)?;

    let matches = build_cli().get_matches();

    if let Some(timing_analysis) = matches.get_one::<String>("timing_analysis") {
        config.app.timing_analysis = timing_analysis.parse::<bool>()?;
    }
    if let Some(timing_analysis_output) = matches.get_one::<String>("timing_analysis_output") {
        config.app.timing_analysis_output = timing_analysis_output.clone();
    }

    Ok(config)
}
