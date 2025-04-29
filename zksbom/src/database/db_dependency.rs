use crate::config::load_config;
use log::{debug, error, info};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

/// Represents a Dependency entry
#[derive(Debug)]
pub struct DependencyDbEntry {
    pub commitment_merkle_tree: String,
    pub commitment_sparse_merkle_tree: String,
    pub dependencies: String,
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
                    commitment_merkle_tree TEXT NOT NULL UNIQUE,
                    commitment_sparse_merkle_tree TEXT NOT NULL UNIQUE,
                    dependencies TEXT NOT NULL,
                    PRIMARY KEY (commitment_merkle_tree, commitment_sparse_merkle_tree)
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
        "INSERT INTO dependency (commitment_merkle_tree, commitment_sparse_merkle_tree, dependencies) VALUES (?1, ?2, ?3)",
        params![dependency.commitment_merkle_tree, dependency.commitment_sparse_merkle_tree, dependency.dependencies],
    ) {
        Ok(_) => info!("Dependency inserted into the database."),
        Err(e) => error!("Error inserting dependency into the database: {}", e),
    };
}

pub fn get_dependencies(commitment: String, method: &str) -> DependencyDbEntry {
    debug!("Getting dependency from the database...");
    let conn = get_db_dependency_conneciton();

    let mut sql_string: &str = "";
    match method {
        "merkle-tree" => {
            sql_string = "SELECT commitment_merkle_tree, commitment_sparse_merkle_tree, dependencies FROM dependency WHERE commitment_merkle_tree = ?1";
        }
        "sparse-merkle-tree" => {
            sql_string = "SELECT commitment_merkle_tree, commitment_sparse_merkle_tree, dependencies FROM dependency WHERE commitment_sparse_merkle_tree =?1";
        }
        "zkp" => {}
        _ => {
            panic!("Unknown method: {}", method);
        }
    }

    let dependency = match conn.query_row(sql_string, rusqlite::params![commitment], |row| {
        Ok(DependencyDbEntry {
            commitment_merkle_tree: row.get(0)?,
            commitment_sparse_merkle_tree: row.get(1)?,
            dependencies: row.get(2)?,
        })
    }) {
        Ok(dependency) => dependency,
        Err(e) => {
            error!("Error getting dependency from the database: {}", e);
            DependencyDbEntry {
                commitment_merkle_tree: "".to_string(),
                commitment_sparse_merkle_tree: "".to_string(),
                dependencies: "".to_string(),
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
