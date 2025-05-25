use crate::config::load_config;
use log::{debug, error};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

/// Represents a Commitment entry
#[derive(Debug)]
pub struct OzksDbEntry {
    pub commitment: String,
    pub zks: String,
    pub config: String,
}

pub fn init_db_ozks() {
    debug!("Initializing the ozks database...");
    let config = load_config().unwrap();
    let db_path = config.db_ozks.path;

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

    // Create the Ozks table if it doesn't exist
    match Connection::open(db_path) {
        Ok(conn) => {
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS ozks (
                    commitment TEXT NOT NULL,
                    zks TEXT NOT NULL,
                    config TEXT NOT NULL,
                    PRIMARY KEY (commitment)
                )",
                [],
            ) {
                Ok(_) => debug!("Ozks database initialized."),
                Err(e) => error!("Error initializing Ozks database: {}", e),
            };
        }
        Err(e) => error!("Error opening database connection: {}", e),
    };
}

fn get_db_ozks_conneciton() -> Connection {
    debug!("Getting the ozks database connection...");
    let config = load_config().unwrap();
    let db_path = config.db_ozks.path;

    match Connection::open(&db_path) {
        Ok(conn) => {
            debug!("Ozks database connection established.");
            conn
        }
        Err(e) => {
            panic!("Error opening database connection: {}", e);
        }
    }
}

pub fn insert_ozks(entry: OzksDbEntry) {
    debug!("Inserting ozks into the database...");
    let conn = get_db_ozks_conneciton();

    match conn.execute(
        "INSERT INTO ozks (commitment, zks, config) VALUES (?1, ?2, ?3)",
        params![
            entry.commitment,
            entry.zks,
            entry.config,
        ],
    ) {
        Ok(_) => debug!("Ozks inserted into the database."),
        Err(e) => error!("Error inserting ozks into the database: {}", e),
    };
}


pub fn get_ozks(commitment: String) -> OzksDbEntry {
    debug!("Getting ozks from the database...");
    let conn = get_db_ozks_conneciton();

    match conn.query_row(
        "SELECT commitment, zks, config FROM ozks WHERE commitment = ?1",
        params![commitment],
        |row| {
            Ok(OzksDbEntry {
                commitment: row.get(0)?,
                zks: row.get(1)?,
                config: row.get(2)?,
            })
        },
    ) {
        Ok(ozks) => ozks,
        Err(e) => {
            error!("Error getting ozks from the database: {}", e);
            OzksDbEntry {
                commitment: "".to_string(),
                zks: "".to_string(),
                config: "".to_string(),
            }
        }
    }
}


pub fn delete_db_ozks() {
    debug!("Deleting the ozks database...");
    let conn = get_db_ozks_conneciton();
    _ = conn.execute("DELETE FROM ozks", []);
}
