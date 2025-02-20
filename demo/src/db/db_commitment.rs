use rusqlite::{Connection, Result, params};
use crate::config::config::load_config;

/// Represents a Commitment entry
#[derive(Debug)]
pub struct Commitment {
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub commitment: String,
    // pub vulnerabilities: Vec<String>,
}

/// Initialize the Commitment database
pub fn init_commitment_db() -> Result<Connection> {
    let config = load_config("./src/config/config.toml").unwrap();
    let db_path = config.commitment_database.path;
    
    let conn = Connection::open(db_path)?;

    // Create the Commitment table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS commitment (
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            commitment TEXT NOT NULL,
            PRIMARY KEY (vendor, product, version)
        )",
        [],
    )?;

    Ok(conn)
}

/// Insert a Commitment entry into the Commitment database
pub fn insert_commitment(conn: &Connection, commitment: &Commitment) -> Result<()> {
    conn.execute(
        "INSERT INTO commitment (vendor, product, version, commitment) VALUES (?1, ?2, ?3, ?4)",
        params![commitment.vendor, commitment.product, commitment.version, commitment.commitment],
    )?;
    Ok(())
}

pub fn get_specific_commitment(conn: &Connection, vendor: &str, product: &str, version: &str) -> Result<Commitment> {
    let mut stmt = conn.prepare("SELECT vendor, product, version, commitment FROM commitment WHERE vendor = ?1 AND product = ?2 AND version = ?3")?;
    let commitment = stmt.query_map(&[&vendor, &product, &version], |row| {
        Ok(Commitment {
            vendor: row.get(0)?,
            product: row.get(1)?,
            version: row.get(2)?,
            commitment: row.get(3)?,
        })
    })?
    .collect::<Result<Vec<_>>>()?;

    if commitment.len() == 0 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    Ok(commitment.into_iter().next().unwrap())
}

pub fn get_commitment_db_connection() -> Connection {
    return init_commitment_db().unwrap();
}

pub fn init_commitment_database() -> Result<(), Box<dyn std::error::Error>> {
    let _commitment_conn = init_commitment_db();
    Ok(())
}
