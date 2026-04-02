use rusqlite::Connection;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zksbom::config::Config;
use zksbom::database::db_commitment::init_db_commitment;
use zksbom::database::db_dependency::init_db_dependency;
use zksbom::upload::upload;

pub fn test_upload_sbom(sbom_path: &str, config: Config) {
    let api_key = "";

    // Check if SBOM file exists
    assert!(
        Path::new(sbom_path).exists(),
        "SBOM file not found at: {}",
        sbom_path
    );

    let db_paths = [
        &config.db_commitment.path,
        &config.db_dependency.path,
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

    // Upload SBOM
    upload(api_key, &sbom_path, &config);

    // Make sure DBs were created
    for db_path in db_paths {
        let path = Path::new(db_path);
        assert!(path.exists(), "Database was not created {:?}!", path);
    }

    // Make sure the content of the DBs is accurate
    test_commitment_db_contents(&config.db_commitment.path, config.app.conceal);
    test_dependency_db_contents(&config.db_dependency.path, config.app.conceal);
    test_ozks_db_contents(&config.db_ozks.path);
}

fn test_commitment_db_contents(db_path: &str, is_concealed: bool) {
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

        // Product information
        assert_eq!(vendor, "unknown");
        assert_eq!(product, "druid");
        assert_eq!(version, "0.22.0");

        let file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        if is_concealed {
            // Merkle Tree
            let mut commitment_file = format!("{}/mt-commitment-concealed.txt", file_prefix);
            let mut expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_merkle_tree, expected_commitment.as_str());

            // Sparse Merkle Tree
            commitment_file = format!("{}/smt-commitment-concealed.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_sparse_merkle_tree, expected_commitment.as_str());

            // Merkle Patricia Trie
            commitment_file = format!("{}/mpt-commitment-concealed.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(
                &commitment_merkle_patricia_trie,
                expected_commitment.as_str()
            );

            // oZKS
            assert_valid_commitment(&commitment_ozks, "commitment_ozks");
        } else {
            // Merkle Tree
            let mut commitment_file = format!("{}/mt-commitment.txt", file_prefix);
            let mut expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_merkle_tree, expected_commitment.as_str());

            // Sparse Merkle Tree
            commitment_file = format!("{}/smt-commitment.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_sparse_merkle_tree, expected_commitment.as_str());

            // Merkle Patricia Trie
            commitment_file = format!("{}/mpt-commitment.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(
                &commitment_merkle_patricia_trie,
                expected_commitment.as_str()
            );

            // oZKS
            assert_valid_commitment(&commitment_ozks, "commitment_ozks");
        }
    } else {
        panic!("No commitment row found in the database");
    }
}

pub fn assert_valid_commitment(commitment: &str, name: &str) {
    assert!(!commitment.is_empty(), "{} should not be empty", name);
    assert!(
        commitment.chars().any(|c| c != '0'),
        "{} is all zeroes!",
        name
    );
}

fn test_dependency_db_contents(db_path: &str, is_concealed: bool) {
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

        let file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        if is_concealed {
            // Merkle Tree
            let mut commitment_file = format!("{}/mt-commitment-concealed.txt", file_prefix);
            let mut expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_merkle_tree, expected_commitment.as_str());

            // Sparse Merkle Tree
            commitment_file = format!("{}/smt-commitment-concealed.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_sparse_merkle_tree, expected_commitment.as_str());

            // Merkle Patricia Trie
            commitment_file = format!("{}/mpt-commitment-concealed.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(
                &commitment_merkle_patricia_trie,
                expected_commitment.as_str()
            );

            // oZKS
            assert_valid_commitment(&commitment_ozks, "commitment_ozks");
        } else {
            // Merkle Tree
            let mut commitment_file = format!("{}/mt-commitment.txt", file_prefix);
            let mut expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_merkle_tree, expected_commitment.as_str());

            // Sparse Merkle Tree
            commitment_file = format!("{}/smt-commitment.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(&commitment_sparse_merkle_tree, expected_commitment.as_str());

            // Merkle Patricia Trie
            commitment_file = format!("{}/mpt-commitment.txt", file_prefix);
            expected_commitment = fs::read_to_string(commitment_file)
                .expect("Should have been able to read the file");
            assert_eq!(
                &commitment_merkle_patricia_trie,
                expected_commitment.as_str()
            );

            // oZKS
            assert_valid_commitment(&commitment_ozks, "commitment_ozks");
        }
    }
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
