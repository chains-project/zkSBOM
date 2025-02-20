use crate::config::load_config;
use rusqlite::{Connection, params};
use log::{debug, info, error};
use std::path::Path;
use std::fs;

/// Represents a Sbom entry
#[derive(Debug)]
pub struct SbomDbEntry {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub sbom: String,
}

pub fn init_db_sbom() {
    debug!("Initializing the sbom database...");
    let config = load_config().unwrap();
    let db_path = config.db_sbom.path;

    // Check if the directory exists, and create it if not
    let db_path_obj = Path::new(&db_path);
    if let Some(parent) = db_path_obj.parent() {
        if !parent.exists() {
            debug!("Creating directory for database: {}", parent.display());
            match fs::create_dir_all(parent) {
                Ok(_) => info!("Database directory created."),
                Err(e) => error!("Error creating database directory: {}", e),
            }
        }
    }

    // Create the Sbom table if it doesn't exist
    match Connection::open(db_path) {
        Ok(conn) => {
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS sbom (
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    sbom TEXT NOT NULL,
                    PRIMARY KEY (vendor, product, version)
                )",
                [],
            ) {
                Ok(_) => info!("Sbom database initialized."),
                Err(e) => error!("Error initializing Sbom database: {}", e),
            };
        }
        Err(e) => error!("Error opening database connection: {}", e),
    };
}

fn get_db_sbom_conneciton() -> Connection {
    debug!("Getting the sbom database connection...");
    let config = load_config().unwrap();
    let db_path = config.db_sbom.path;

    match Connection::open(&db_path) {
        Ok(conn) => {
            info!("Sbom database connection established.");
            conn
        }
        Err(e) => {
            panic!("Error opening database connection: {}", e);
        }
    }
}

pub fn insert_sbom(sbom: SbomDbEntry) {
    debug!("Inserting sbom into the database...");
    let conn = get_db_sbom_conneciton();

    match conn.execute(
        "INSERT INTO sbom (vendor, product, version, sbom) VALUES (?1, ?2, ?3, ?4)",
        params![sbom.vendor, sbom.product, sbom.version, sbom.sbom],
    ) {
        Ok(_) => info!("Sbom inserted into the database."),
        Err(e) => error!("Error inserting sbom into the database: {}", e),
    };
}

pub fn get_sbom(vendor: String, product: String, version: String) -> SbomDbEntry {
    debug!("Getting sbom from the database...");
    let conn = get_db_sbom_conneciton();

    let sbom = match conn.query_row(
        "SELECT vendor, product, version, sbom FROM sbom WHERE vendor = ?1 AND product = ?2 AND version = ?3",
        rusqlite::params![vendor, product, version],
        |row| {
            Ok(SbomDbEntry {
                vendor: row.get(0)?,
                product: row.get(1)?,
                version: row.get(2)?,
                sbom: row.get(3)?,
            })
        },
    ) {
        Ok(sbom) => sbom,
        Err(e) => {
            error!("Error getting sbom from the database: {}", e);
            SbomDbEntry {
                vendor: "".to_string(),
                product: "".to_string(),
                version: "".to_string(),
                sbom: "".to_string(),
            }
        }
    };

    sbom
}

pub fn delete_db_sbom() {
    debug!("Deleting the sbom database...");
    let conn = get_db_sbom_conneciton();
    _ = conn.execute("DELETE FROM sbom", []);
}
