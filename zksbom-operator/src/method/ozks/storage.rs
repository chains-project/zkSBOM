use rusqlite::{params, Connection};
use std::error::Error;

/// SQLite BatchStorage implementation for persisting oZKS trie structure
pub struct SQLiteBatchStorage {
    db: Connection,
    db_path: String,
}

impl SQLiteBatchStorage {
    /// Create new SQLite storage backend
    pub fn new(db_path: &str) -> Result<Self, Box<dyn Error>> {
        let db = Connection::open(db_path)?;
        db.execute_batch("PRAGMA foreign_keys = ON;")?;

        let mut storage = SQLiteBatchStorage {
            db,
            db_path: db_path.to_string(),
        };

        storage.initialize_database()?;
        Ok(storage)
    }

    /// Initialize database schema (same as C++ version)
    fn initialize_database(&mut self) -> Result<(), Box<dyn Error>> {
        let schema = r#"
            CREATE TABLE IF NOT EXISTS ct_nodes (
                trie_id   INTEGER NOT NULL,
                label     BLOB    NOT NULL,
                data      BLOB    NOT NULL,
                PRIMARY KEY (trie_id, label)
            );

            CREATE TABLE IF NOT EXISTS compressed_tries (
                trie_id   INTEGER PRIMARY KEY,
                data      BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS store_elements (
                trie_id   INTEGER NOT NULL,
                key       BLOB    NOT NULL,
                payload   BLOB    NOT NULL,
                randomness BLOB   NOT NULL,
                PRIMARY KEY (trie_id, key)
            );

            CREATE TABLE IF NOT EXISTS ozks_data (
                trie_id   INTEGER PRIMARY KEY,
                data      BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instance_manifest (
                instance_index  INTEGER PRIMARY KEY,
                trie_id         INTEGER NOT NULL,
                name            TEXT    NOT NULL
            );
        "#;

        self.db.execute_batch(schema)?;
        Ok(())
    }

    /// Save instance manifest entry (maps creation order to trie_id)
    pub fn save_instance_manifest(
        &self,
        instance_index: i32,
        trie_id: i64,
        name: &str,
    ) -> Result<(), Box<dyn Error>> {
        let mut stmt = self.db.prepare(
            "INSERT OR REPLACE INTO instance_manifest (instance_index, trie_id, name) \
             VALUES (?, ?, ?);",
        )?;
        stmt.execute(params![instance_index, trie_id, name])?;
        Ok(())
    }

    /// Load instance manifest - returns vec of (index, (trie_id, name))
    pub fn load_instance_manifest(&self) -> Result<Vec<(i32, (i64, String))>, Box<dyn Error>> {
        let mut stmt = self.db.prepare(
            "SELECT instance_index, trie_id, name FROM instance_manifest ORDER BY instance_index;",
        )?;

        let result = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, String>(2)?),
            ))
        })?;

        let mut manifest = Vec::new();
        for row_result in result {
            manifest.push(row_result?);
        }
        Ok(manifest)
    }

    /// Save OZKS metadata (VRF key, config, etc.)
    pub fn save_ozks_data(&self, trie_id: i64, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut stmt = self
            .db
            .prepare("INSERT OR REPLACE INTO ozks_data (trie_id, data) VALUES (?, ?);")?;
        stmt.execute(params![trie_id, data])?;
        Ok(())
    }

    /// Load OZKS metadata
    pub fn load_ozks_data(&self, trie_id: i64) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut stmt = self
            .db
            .prepare("SELECT data FROM ozks_data WHERE trie_id = ?;")?;

        let result = stmt.query_row(params![trie_id], |row| row.get::<_, Vec<u8>>(0));

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Get the next available instance index
    pub fn next_instance_index(&self) -> Result<i32, Box<dyn Error>> {
        let mut stmt = self
            .db
            .prepare("SELECT COALESCE(MAX(instance_index), -1) + 1 FROM instance_manifest;")?;
        let idx: i32 = stmt.query_row([], |row| row.get(0))?;
        Ok(idx)
    }

    /// Get database path
    pub fn path(&self) -> &str {
        &self.db_path
    }
}
