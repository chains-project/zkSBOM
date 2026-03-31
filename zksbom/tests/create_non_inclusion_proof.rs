use std::fs;
use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::create_proof_no_commitment;

pub fn test_create_non_inclusion_proof() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";

    let methods = ["sparse-merkle-tree", "merkle-patricia-trie", "ozks"];

    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let check = "CVE-2025-55182";
    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        let proof_path = config.app.output.clone();
        let proof_content =
            fs::read_to_string(proof_path).expect("Should have been able to read the file");

        let expected_file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        match method {
            "sparse-merkle-tree" => {
                let file_path = format!("{}/smt-non-inclusion-proof.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "merkle-patricia-trie" => {
                let file_path = format!("{}/mpt-non-inclusion-proof.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "ozks" => {
                crate::create_inclusion_proof::assert_valid_proof(proof_content.as_str(), "ozks");
            }
            _ => panic!("Unknown method: {}", method),
        }
    }
}

pub fn test_create_non_inclusion_proof_dependency() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";

    let methods = ["sparse-merkle-tree", "merkle-patricia-trie", "ozks"];

    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let check = "foo@0.0.1@foo";
    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        let proof_path = config.app.output.clone();
        let proof_content =
            fs::read_to_string(proof_path).expect("Should have been able to read the file");

        let expected_file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        match method {
            "sparse-merkle-tree" => {
                let file_path = format!("{}/smt-non-inclusion-proof-dep.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "merkle-patricia-trie" => {
                let file_path = format!("{}/mpt-non-inclusion-proof-dep.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "ozks" => {
                crate::create_inclusion_proof::assert_valid_proof(proof_content.as_str(), "ozks");
            }
            _ => panic!("Unknown method: {}", method),
        }
    }
}
