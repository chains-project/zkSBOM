use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sbom_database: DatabaseConfig,
    pub commitment_database: DatabaseConfig,
    pub app: AppConfig,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub debug: bool,
    pub log_level: String,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}
