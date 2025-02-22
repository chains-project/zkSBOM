use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub db_commitment: DatabaseConfig,
    pub db_sbom: DatabaseConfig,
    pub db_vulnerability: DatabaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
    pub output: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = "./config/config.toml";
    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
