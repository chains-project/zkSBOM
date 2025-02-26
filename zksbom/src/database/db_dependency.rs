use crate::config::load_config;
use log::{debug, error, info};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

/// Represents a Dependency entry
#[derive(Debug)]
pub struct DependencyDbEntry {
    pub dependencies: String,
    pub commitment: String,
}

pub fn init_db_dependency() {
    debug!("Initializing the dependency database...");
    let config = load_config().unwrap();
    let db_path = config.db_dependency.path;

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

    // Create the Dependency table if it doesn't exist
    match Connection::open(db_path) {
        Ok(conn) => {
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS dependency (
                    dependencies TEXT NOT NULL,
                    commitment TEXT NOT NULL,
                    PRIMARY KEY (commitment)
                )",
                [],
            ) {
                Ok(_) => info!("Dependency database initialized."),
                Err(e) => error!("Error initializing Dependency database: {}", e),
            };
        }
        Err(e) => error!("Error opening database connection: {}", e),
    };
}

fn get_db_dependency_conneciton() -> Connection {
    debug!("Getting the dependency database connection...");
    let config = load_config().unwrap();
    let db_path = config.db_dependency.path;

    match Connection::open(&db_path) {
        Ok(conn) => {
            info!("Dependency database connection established.");
            conn
        }
        Err(e) => {
            panic!("Error opening database connection: {}", e);
        }
    }
}

pub fn insert_dependency(dependency: DependencyDbEntry) {
    debug!("Inserting dependency into the database...");
    let conn = get_db_dependency_conneciton();

    match conn.execute(
        "INSERT INTO dependency (dependencies, commitment) VALUES (?1, ?2)",
        params![dependency.dependencies, dependency.commitment],
    ) {
        Ok(_) => info!("Dependency inserted into the database."),
        Err(e) => error!("Error inserting dependency into the database: {}", e),
    };
}

pub fn get_dependencies(commitment: String) -> DependencyDbEntry {
    debug!("Getting dependency from the database...");
    let conn = get_db_dependency_conneciton();

    let dependency = match conn.query_row(
        "SELECT dependencies, commitment FROM dependency WHERE commitment = ?1",
        rusqlite::params![commitment],
        |row| {
            Ok(DependencyDbEntry {
                dependencies: row.get(0)?,
                commitment: row.get(1)?,
            })
        },
    ) {
        Ok(dependency) => dependency,
        Err(e) => {
            error!("Error getting dependency from the database: {}", e);
            DependencyDbEntry {
                dependencies: "".to_string(),
                commitment: "".to_string(),
            }
        }
    };

    dependency
}

pub fn delete_db_dependency() {
    debug!("Deleting the dependency database...");
    let conn = get_db_dependency_conneciton();
    _ = conn.execute("DELETE FROM dependency", []);
}
