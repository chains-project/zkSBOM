use rusqlite::Connection;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zksbom::config::load_config_from_file;
use zksbom::database::db_commitment::init_db_commitment;
use zksbom::database::db_dependency::init_db_dependency;
use zksbom::database::db_vulnerabilities::init_db_vulnerabilities;
use zksbom::upload::upload;

pub fn test_upload_sbom(config_path: &str) {
    let api_key = "";
    let sbom_path = "../sboms/other/test_sbom_openssl.cdx.json";

    // Check if SBOM file exists
    assert!(
        Path::new(sbom_path).exists(),
        "SBOM file not found at: {}",
        sbom_path
    );

    let config = load_config_from_file(config_path).unwrap();

    let db_paths = [
        &config.db_commitment.path,
        &config.db_dependency.path,
        &config.db_vulnerabilities.path,
        &config.db_ozks.path,
    ];

    // Clean up any existing databases
    for db_path in &db_paths {
        let path = Path::new(db_path);
        if path.exists() {
            fs::remove_file(path).expect("Failed to remove existing database");
        }
    }

    // Initialize the databases with their schemas
    init_db_commitment(&config);
    init_db_dependency(&config);
    init_db_vulnerabilities(&config);

    // Upload SBOM
    upload(api_key, &sbom_path, &config);

    // Make sure DBs were created
    for db_path in db_paths {
        let path = Path::new(db_path);
        assert!(path.exists(), "Database was not created {:?}!", path);
    }

    // Make sure the content of the DBs is accurate
    test_commitment_db_contents(&config.db_commitment.path);
    test_dependency_db_contents(&config.db_dependency.path);
    test_vulnerability_db_contents(&config.db_vulnerabilities.path);
    test_ozks_db_contents(&config.db_ozks.path);
}

fn test_commitment_db_contents(db_path: &str) {
    assert!(Path::new(db_path).exists(), "Commitment DB does not exist!");

    // Open SQLite connection
    let conn = Connection::open(db_path).expect("Failed to open commitment DB");

    // Query the expected values
    let mut stmt = conn
        .prepare(
            "SELECT vendor, product, version, commitment_merkle_tree, commitment_sparse_merkle_tree, commitment_merkle_patricia_trie, commitment_ozks FROM commitment"
        )
        .expect("Failed to prepare statement");

    let mut rows = stmt.query([]).expect("Failed to query commitments table");

    if let Some(row) = rows.next().expect("Failed to iterate rows") {
        // Check expected values
        let vendor: String = row.get(0).unwrap();
        let product: String = row.get(1).unwrap();
        let version: String = row.get(2).unwrap();
        let commitment_merkle_tree: String = row.get(3).unwrap();
        let commitment_sparse_merkle_tree: String = row.get(4).unwrap();
        let commitment_merkle_patricia_trie: String = row.get(5).unwrap();
        let commitment_ozks: String = row.get(6).unwrap();

        assert_eq!(vendor, "Tom Sorger <sorger@kth.se>");
        assert_eq!(product, "test_openssl");
        assert_eq!(version, "0.1.0");
        assert_eq!(
            commitment_merkle_tree,
            "0x147371669a559c8f9daaccee3d98f37d8850377882d2fd6e4d94079c861e7ae4"
        );
        assert_eq!(
            commitment_sparse_merkle_tree,
            "0x949650e05725a7dd3415982d89315dcbc3f5bac994a97b4c1b60ac7c0695c4a7"
        );
        assert_eq!(
            commitment_merkle_patricia_trie,
            "0xf67ab4fdac9fa1a5db9c0c42d6b95517fbf24cc9108d7a8156e805841f9f6e1a"
        );
        assert!(
            commitment_ozks.chars().any(|c| c != '0'),
            "oZKS commitment is all zeroes!"
        );
    } else {
        panic!("No commitment row found in the database");
    }
}

fn test_dependency_db_contents(db_path: &str) {
    assert!(Path::new(db_path).exists(), "Dependency DB does not exist!");

    // Open SQLite connection
    let conn = Connection::open(db_path).expect("Failed to open dependency DB");

    // Query the expected values
    let mut stmt = conn
        .prepare(
            "SELECT commitment_merkle_tree, commitment_sparse_merkle_tree, commitment_merkle_patricia_trie, commitment_ozks, dependencies FROM dependency"
        )
        .expect("Failed to prepare statement");

    let mut rows = stmt.query([]).expect("Failed to query commitments table");

    if let Some(row) = rows.next().expect("Failed to iterate rows") {
        // Check expected values
        let commitment_merkle_tree: String = row.get(0).unwrap();
        let commitment_sparse_merkle_tree: String = row.get(1).unwrap();
        let commitment_merkle_patricia_trie: String = row.get(2).unwrap();
        let commitment_ozks: String = row.get(3).unwrap();
        let dependencies: String = row.get(4).unwrap();

        assert_eq!(
            commitment_merkle_tree,
            "0x147371669a559c8f9daaccee3d98f37d8850377882d2fd6e4d94079c861e7ae4"
        );
        assert_eq!(
            commitment_sparse_merkle_tree,
            "0x949650e05725a7dd3415982d89315dcbc3f5bac994a97b4c1b60ac7c0695c4a7"
        );
        assert_eq!(
            commitment_merkle_patricia_trie,
            "0xf67ab4fdac9fa1a5db9c0c42d6b95517fbf24cc9108d7a8156e805841f9f6e1a"
        );
        assert!(
            commitment_ozks.chars().any(|c| c != '0'),
            "oZKS commitment is all zeroes!"
        );
        assert_eq!(
            dependencies,
            "openssl@0.10.1@RUST,openssl@0.11.1@GO,openssl@0.12.1@MAVEN,\
            openssl@RUST,openssl@GO,openssl@MAVEN"
        );
    } else {
        panic!("No commitment row found in the database");
    }
}

fn test_vulnerability_db_contents(db_path: &str) {
    assert!(
        Path::new(db_path).exists(),
        "Vulnerability DB does not exist!"
    );

    let conn = Connection::open(db_path).expect("Failed to open vulnerability DB");

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
        .expect("Failed to execute count query");

    assert_eq!(
        count, 0,
        "Expected vulnerabilities table to be empty, but found {} row(s)",
        count
    );
}

fn test_ozks_db_contents(db_path: &str) {
    assert!(Path::new(db_path).exists(), "oZKS DB does not exist!");

    let expected_tables: HashMap<&str, Vec<&str>> = [
        ("compressed_tries", vec!["trie_id", "data"]),
        ("ct_nodes", vec!["trie_id", "label", "data"]),
        (
            "instance_manifest",
            vec!["instance_index", "trie_id", "name"],
        ),
        ("ozks_data", vec!["trie_id", "data"]),
        (
            "store_elements",
            vec!["trie_id", "key", "payload", "randomness"],
        ),
    ]
    .iter()
    .cloned()
    .collect();

    let conn = Connection::open(db_path).expect("Failed to open ozks DB");

    for (table, columns) in &expected_tables {
        let table_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
                [*table],
                |row| row.get(0),
            )
            .expect("Failed to execute query");
        assert!(table_exists, "Table '{}' does not exist!", table);

        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", table))
            .expect("Failed to prepare statement");
        let table_columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .expect("Failed to execute query")
            .collect::<Result<Vec<String>, _>>()
            .expect("Failed to get table columns");
        for col in columns {
            assert!(
                table_columns.contains(&col.to_string()),
                "Table '{}' does not have expected column '{}'",
                table,
                col
            );
        }

        // Check at least 1 entry in table
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {}", table), [], |row| {
                row.get(0)
            })
            .expect("Failed to execute count query");
        assert!(count > 0, "Table '{}' is empty!", table);
    }
}
