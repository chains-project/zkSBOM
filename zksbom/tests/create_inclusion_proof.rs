use std::fs;
use zksbom::config::{load_config_from_file, Config};
use zksbom::method::method_handler::create_proof_no_commitment;

pub fn test_create_inclusion_proof(config: Config) {
    let api_key = "";
    let methods = [
        "merkle-tree",
        "sparse-merkle-tree",
        "merkle-patricia-trie",
        "ozks",
    ];

    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let check = "CVE-2021-44228";

    for method in methods {
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        let proof_path = config.app.output.clone();
        let proof_content = fs::read_to_string(proof_path).expect(
            format!(
                "Should have been able to read the file for method: {}",
                method
            )
            .as_str(),
        );

        let expected_file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        if config.app.conceal {
            match method {
                "merkle-tree" => {
                    let file_path =
                        format!("{}/mt-inclusion-proof-concealed.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "sparse-merkle-tree" => {
                    let file_path =
                        format!("{}/smt-inclusion-proof-concealed.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "merkle-patricia-trie" => {
                    let file_path =
                        format!("{}/mpt-inclusion-proof-concealed.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "ozks" => {
                    assert_valid_proof(proof_content.as_str(), "ozks");
                }
                _ => panic!("Unknown method: {}", method),
            }
        } else {
            match method {
                "merkle-tree" => {
                    let file_path = format!("{}/mt-inclusion-proof.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "sparse-merkle-tree" => {
                    let file_path = format!("{}/smt-inclusion-proof.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "merkle-patricia-trie" => {
                    let file_path = format!("{}/mpt-inclusion-proof.txt", expected_file_prefix);
                    let expected_content = fs::read_to_string(file_path)
                        .expect("Should have been able to read the file");

                    assert_eq!(proof_content, expected_content);
                }
                "ozks" => {
                    assert_valid_proof(proof_content.as_str(), "ozks");
                }
                _ => panic!("Unknown method: {}", method),
            }
        }
    }
}

pub fn assert_valid_proof(proof: &str, name: &str) {
    assert!(!proof.is_empty(), "{} should not be empty", name);
    assert!(proof.chars().any(|c| c != '0'), "{} is all zeroes!", name);
}

#[allow(dead_code)] // This is **no** dead code. Rust doesn't recognize this when splitting tests into multiple files
pub fn test_create_inclusion_proof_dependency() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";

    let methods = [
        "merkle-tree",
        "sparse-merkle-tree",
        "merkle-patricia-trie",
        "ozks",
    ];

    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let check = "org.apache.logging.log4j:log4j-core@2.4@MAVEN";
    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        let proof_path = config.app.output.clone();
        let proof_content =
            fs::read_to_string(proof_path).expect("Should have been able to read the file");

        let expected_file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        match method {
            "merkle-tree" => {
                let file_path = format!("{}/mt-inclusion-proof-dep.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "sparse-merkle-tree" => {
                let file_path = format!("{}/smt-inclusion-proof-dep.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "merkle-patricia-trie" => {
                let file_path = format!("{}/mpt-inclusion-proof-dep.txt", expected_file_prefix);
                let expected_content =
                    fs::read_to_string(file_path).expect("Should have been able to read the file");

                assert_eq!(proof_content, expected_content);
            }
            "ozks" => {
                assert_valid_proof(proof_content.as_str(), "ozks");
            }
            _ => panic!("Unknown method: {}", method),
        }
    }
}
