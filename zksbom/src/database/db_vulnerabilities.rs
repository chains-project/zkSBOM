use crate::config::load_config;
use log::{debug, error};
use rusqlite::{params, Connection, Result};
use std::fs;
use std::path::Path;

/// Represents a vulnerability entry
#[derive(Debug)]
pub struct VulnerabilityDbEntry {
    pub dependency: String,
    pub vulnerabilities: String, // comma-separated string
}

pub fn init_db_vulnerabilities() {
    debug!("Initializing the vulnerabilities database...");
    let config = load_config().unwrap();
    let db_path = config.db_vulnerabilities.path;

    // Check if the directory exists, and create it if not
    let db_path_obj = Path::new(&db_path);
    if let Some(parent) = db_path_obj.parent() {
        if !parent.exists() {
            debug!("Creating directory for database: {}", parent.display());
            match fs::create_dir_all(parent) {
                Ok(_) => debug!("Database directory created."),
                Err(e) => error!("Error creating database directory: {}", e),
            }
        }
    }

    // Create the Vulnerability table if it doesn't exist.
    match Connection::open(db_path) {
        Ok(conn) => {
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS vulnerabilities (
                    dependency TEXT NOT NULL PRIMARY KEY,
                    vulnerabilities_list TEXT NOT NULL
                )",
                [],
            ) {
                Ok(_) => debug!("Vulnerabilities database initialized."),
                Err(e) => error!("Error initializing db_vulnerabilitiesulnerabilities database: {}", e),
            };
        }
        Err(e) => error!("Error opening database connection: {}", e),
    };
}

fn get_db_vulnerabilities_connection() -> Connection {
    debug!("Getting the db_vulnerabilities database connection...");
    let config = load_config().unwrap();
    let db_path = config.db_vulnerabilities.path;

    match Connection::open(&db_path) {
        Ok(conn) => {
            debug!("Vulnerabilities database connection established.");
            conn
        }
        Err(e) => {
            panic!("Error opening database connection: {}", e);
        }
    }
}

/// Inserts a new dependency and its vulnerabilities into the database.
/// If the dependency already exists, it will be overwritten.
pub fn insert_vulnerabilities(entry: VulnerabilityDbEntry) -> Result<()> {
    error!("Inserting vulnerability into the database...");
    let conn = get_db_vulnerabilities_connection();

    conn.execute(
        "INSERT OR REPLACE INTO vulnerabilities (dependency, vulnerabilities_list) VALUES (?1, ?2)",
        params![entry.dependency, entry.vulnerabilities],
    )?;
    error!("Vulnerability inserted into the database.");
    Ok(())
}

/// Retrieves the vulnerabilities for a given dependency.
pub fn get_vulnerabilities(dependency: &str) -> Result<Option<Vec<String>>> {
    debug!("Getting vulnerabilities from the database for dependency: {}", dependency);
    let conn = get_db_vulnerabilities_connection();

    let mut stmt = conn.prepare(
        "SELECT vulnerabilities_list FROM vulnerabilities WHERE dependency = ?1",
    )?;
    let mut rows = stmt.query(params![dependency])?;

    if let Some(row) = rows.next()? {
        let vulnerabilities_str: String = row.get(0)?;
        let vulnerabilities: Vec<String> = vulnerabilities_str
            .split(',')
            .map(|s| s.to_string())
            .collect();
        debug!("Found vulnerabilities: {:?} for dependency: {}", vulnerabilities, dependency);
        Ok(Some(vulnerabilities))
    } else {
        debug!("No vulnerabilities found for dependency: {}", dependency);
        Ok(None)
    }
}

pub fn delete_db_vulnerabilities() {
    debug!("Deleting the vulnerability database...");
    let conn = get_db_vulnerabilities_connection();
    _ = conn.execute("DELETE FROM vulnerabilities", []);
}
