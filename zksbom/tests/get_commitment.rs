use std::fs;
use zksbom::config::Config;
use zksbom::method::method_handler::get_commitment;

pub fn test_get_commitment(config: Config) {
    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let methods = [
        "merkle-tree",
        "sparse-merkle-tree",
        "merkle-patricia-trie",
        "ozks",
    ];

    for method in methods {
        let commitment = get_commitment(vendor, product, version, method, &config);
        let file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

        if config.app.conceal {
            match method {
                "merkle-tree" => {
                    let commitment_file = format!("{}/mt-commitment-concealed.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "sparse-merkle-tree" => {
                    let commitment_file = format!("{}/smt-commitment-concealed.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "merkle-patricia-trie" => {
                    let commitment_file = format!("{}/mpt-commitment-concealed.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "ozks" => {
                    assert_valid_commitment(&commitment, "ozks-commitment-concealed");
                }
                _ => panic!("Unknown method: {}", method),
            }
        } else {
            match method {
                "merkle-tree" => {
                    let commitment_file = format!("{}/mt-commitment.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "sparse-merkle-tree" => {
                    let commitment_file = format!("{}/smt-commitment.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "merkle-patricia-trie" => {
                    let commitment_file = format!("{}/mpt-commitment.txt", file_prefix);
                    let expected_commitment = fs::read_to_string(commitment_file)
                        .expect("Should have been able to read the file");
                    assert_eq!(&commitment, expected_commitment.as_str());
                }
                "ozks" => {
                    assert_valid_commitment(&commitment, "commitment_ozks");
                }
                _ => panic!("Unknown method: {}", method),
            }
        }
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
