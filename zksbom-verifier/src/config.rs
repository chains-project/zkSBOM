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

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = "./config/config.toml";
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;

    let matches = build_cli().get_matches();

    if let Some(timing_analysis) = matches.get_one::<String>("timing_analysis") {
        config.app.timing_analysis = timing_analysis.parse::<bool>()?;
    }
    if let Some(timing_analysis_output) = matches.get_one::<String>("timing_analysis_output") {
        config.app.timing_analysis_output = timing_analysis_output.clone();
    }

    Ok(config)
}
