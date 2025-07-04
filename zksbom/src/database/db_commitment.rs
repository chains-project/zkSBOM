use crate::config::load_config;
use log::{debug, error};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

/// Represents a Commitment entry
#[derive(Debug)]
pub struct CommitmentDbEntry {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub commitment_merkle_tree: String,
    pub commitment_sparse_merkle_tree: String,
    pub commitment_merkle_patricia_trie: String,
    pub commitment_ozks: String,
}

pub fn init_db_commitment() {
    debug!("Initializing the commitment database...");
    let config = load_config().unwrap();
    let db_path = config.db_commitment.path;

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

    // Create the Commitment table if it doesn't exist
    match Connection::open(db_path) {
        Ok(conn) => {
            match conn.execute(
                "CREATE TABLE IF NOT EXISTS commitment (
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    version TEXT NOT NULL,
                    commitment_merkle_tree TEXT NOT NULL,
                    commitment_sparse_merkle_tree TEXT NOT NULL,
                    commitment_merkle_patricia_trie TEXT NOT NULL,
                    commitment_ozks TEXT NOT NULL,
                    PRIMARY KEY (vendor, product, version)
                )",
                [],
            ) {
                Ok(_) => debug!("Commitment database initialized."),
                Err(e) => error!("Error initializing Commitment database: {}", e),
            };
        }
        Err(e) => error!("Error opening database connection: {}", e),
    };
}

fn get_db_commitment_conneciton() -> Connection {
    debug!("Getting the commitment database connection...");
    let config = load_config().unwrap();
    let db_path = config.db_commitment.path;

    match Connection::open(&db_path) {
        Ok(conn) => {
            debug!("Commitment database connection established.");
            conn
        }
        Err(e) => {
            panic!("Error opening database connection: {}", e);
        }
    }
}

pub fn insert_commitment(commitment: CommitmentDbEntry) {
    debug!("Inserting commitment into the database...");
    let conn = get_db_commitment_conneciton();

    match conn.execute(
        "INSERT INTO commitment (vendor, product, version, commitment_merkle_tree, commitment_sparse_merkle_tree, commitment_merkle_patricia_trie, commitment_ozks) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            commitment.vendor,
            commitment.product,
            commitment.version,
            commitment.commitment_merkle_tree,
            commitment.commitment_sparse_merkle_tree,
            commitment.commitment_merkle_patricia_trie,
            commitment.commitment_ozks,
        ],
    ) {
        Ok(_) => debug!("Commitment inserted into the database."),
        Err(e) => error!("Error inserting commitment into the database: {} (vendor: {}, product: {}, version: {})", e, commitment.vendor, commitment.product, commitment.version),
    };
}

pub fn get_commitment(vendor: String, product: String, version: String) -> CommitmentDbEntry {
    debug!("Getting commitment from the database...");
    let conn = get_db_commitment_conneciton();

    let commitment = match conn.query_row(
        "SELECT vendor, product, version, commitment_merkle_tree, commitment_sparse_merkle_tree, commitment_merkle_patricia_trie, commitment_ozks FROM commitment WHERE vendor = ?1 AND product = ?2 AND version = ?3",
        rusqlite::params![vendor, product, version],
        |row| {
            Ok(CommitmentDbEntry {
                vendor: row.get(0)?,
                product: row.get(1)?,
                version: row.get(2)?,
                commitment_merkle_tree: row.get(3)?,
                commitment_sparse_merkle_tree: row.get(4)?,
                commitment_merkle_patricia_trie: row.get(5)?,
                commitment_ozks: row.get(6)?,
            })
        },
    ) {
        Ok(commitment) => commitment,
        Err(e) => {
            error!("Error getting commitment from the database: {}", e);
            CommitmentDbEntry {
                vendor: "".to_string(),
                product: "".to_string(),
                version: "".to_string(),
                commitment_merkle_tree: "".to_string(),
                commitment_sparse_merkle_tree: "".to_string(),
                commitment_merkle_patricia_trie: "".to_string(),
                commitment_ozks: "".to_string(),
            }
        }
    };

    commitment
}

pub fn delete_db_commitment() {
    debug!("Deleting the commitment database...");
    let conn = get_db_commitment_conneciton();
    _ = conn.execute("DELETE FROM commitment", []);
}
