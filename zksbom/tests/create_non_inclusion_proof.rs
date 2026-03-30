use std::fs;
use std::path::Path;
use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::create_proof_no_commitment;

pub fn test_create_non_inclusion_proof() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";

    let methods = ["sparse-merkle-tree", "merkle-patricia-trie", "ozks"];

    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "CVE-2023-4863";
    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Rename/move the proof file to avoid overwriting
        fs::rename(path, &new_path)
            .unwrap_or_else(|e| panic!("Failed to rename proof file for {method}: {e}"));
    }

    // Remove last file from the tests:
    let dir = Path::new(&config.app.output)
        .parent()
        .expect("No parent dir");

    // Iterate over entries in the directory
    for entry in fs::read_dir(dir).expect("Failed to read dir") {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        // Remove only files, not directories
        if path.is_file() {
            let _ = fs::remove_file(&path);
        }
    }

    // Verify proof files
    for method in methods {
        let output = config.app.output.clone();

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof.txt");
        let new_path = inclusion_dir.join(&new_filename);

        let actual_content = fs::read_to_string(&new_path)
            .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
        assert_valid_proof(&actual_content, method)
    }
}

pub fn assert_valid_proof(proof: &str, name: &str) {
    assert!(!proof.is_empty(), "{} should not be empty", name);
    assert!(proof.chars().any(|c| c != '0'), "{} is all zeroes!", name);
}

pub fn test_create_non_inclusion_proof_dependency() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";

    let methods = ["sparse-merkle-tree", "merkle-patricia-trie", "ozks"];

    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "foo@0.0.1@foo";
    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof-dep.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Rename/move the proof file to avoid overwriting
        fs::rename(path, &new_path)
            .unwrap_or_else(|e| panic!("Failed to rename proof file for {method}: {e}"));
    }

    // Remove last file from the tests:
    let dir = Path::new(&config.app.output)
        .parent()
        .expect("No parent dir");

    // Iterate over entries in the directory
    for entry in fs::read_dir(dir).expect("Failed to read dir") {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        // Remove only files, not directories
        if path.is_file() {
            let _ = fs::remove_file(&path);
        }
    }

    // Verify proof files
    for method in methods {
        let output = config.app.output.clone();

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof-dep.txt");
        let new_path = inclusion_dir.join(&new_filename);

        let actual_content = fs::read_to_string(&new_path)
            .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
        assert_valid_proof(&actual_content, method);
    }
}
