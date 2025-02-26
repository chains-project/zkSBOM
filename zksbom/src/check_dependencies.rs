use crate::config::load_config;
use log::{debug, error, info};
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

fn is_url_available(url: &str) -> bool {
    let client = Client::new();

    match client
        .get(url)
        .header(USER_AGENT, "Mozilla/5.0 (compatible; RustBot/1.0)")
        .send()
    {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

pub fn check_dependencies(dependencies: &Vec<String>) {
    let config = load_config().unwrap();
    let log_path = config.app.check_dependencies_output;
    // if let Err(e) = fs::create_dir_all("./tmp/output") {
    //     error!("Failed to create directory: {}", e);
    //     return;
    // }
    // Check if the directory exists, and create it if not
    let log_path_obj = Path::new(&log_path);
    if let Some(parent) = log_path_obj.parent() {
        if !parent.exists() {
            debug!(
                "Creating directory for checking dependencies: {}",
                parent.display()
            );
            match fs::create_dir_all(parent) {
                Ok(_) => info!("Dependency check directory created."),
                Err(e) => error!("Error creating dependency check directory: {}", e),
            }
        }
    }

    let mut log_file = match OpenOptions::new().append(true).create(true).open(&log_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open log file: {}", e);
            return;
        }
    };

    for dependency in dependencies {
        if let Some((crate_name, version)) = dependency.split_once('@') {
            let url = format!("https://crates.io/api/v1/crates/{}/{}", crate_name, version);
            if !is_url_available(&url) {
                let log_entry = format!(
                    "Dependency called \"{}\" with version \"{}\" not found at \"{}\".\n",
                    crate_name, version, url
                );
                if let Err(e) = log_file.write_all(log_entry.as_bytes()) {
                    error!("Failed to write to log file: {}", e);
                }
            }
        } else {
            error!("Invalid dependency format: {}", dependency);
        }
    }

    info!(
        "Dependency check complete. Check the log file for details '{}'.",
        &log_path
    );
}
