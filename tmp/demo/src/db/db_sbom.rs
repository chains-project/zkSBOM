use rusqlite::{Connection, Result};
use crate::config::config::load_config;

/// Represents an SBOM entry
#[derive(Debug)]
pub struct Sbom {
    pub sbom: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
}

/// Initialize the SBOM database
pub fn init_sbom_db() -> Result<Connection> {
    let config = load_config("./src/config/config.toml").unwrap();
    let db_path = config.sbom_database.path;

    let conn = Connection::open(db_path)?;

    // Create the SBOM table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sbom (
            sbom TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            PRIMARY KEY (vendor, product, version)
        )",
        [],
    )?;

    Ok(conn)
}

/// Insert an SBOM entry into the SBOM database
pub fn insert_sbom(conn: &Connection, sbom: &Sbom) -> Result<()> {
    conn.execute(
        "INSERT INTO sbom (sbom, vendor, product, version) VALUES (?1, ?2, ?3, ?4)",
        &[&sbom.sbom, &sbom.vendor, &sbom.product, &sbom.version],
    )?;
    Ok(())
}

pub fn get_specific_sbom(conn: &Connection, vendor: &str, product: &str, version: &str) -> Result<Sbom> {
    let mut stmt = conn.prepare("SELECT sbom, vendor, product, version FROM sbom WHERE vendor = ?1 AND product = ?2 AND version = ?3")?;
    let sbom = stmt.query_map(&[&vendor, &product, &version], |row| {
        Ok(Sbom {
            sbom: row.get(0)?,
            vendor: row.get(1)?,
            product: row.get(2)?,
            version: row.get(3)?,
        })
    })?
    .next()
    .unwrap()
    .unwrap();

    Ok(sbom)
}

pub fn get_sbom_db_connection() -> Connection {
    return init_sbom_db().unwrap();
}

pub fn init_sbom_database() -> Result<(), Box<dyn std::error::Error>> {
    let _sbom_conn = init_sbom_db();
    Ok(())
}
