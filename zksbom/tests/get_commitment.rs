use std::fs;
use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::get_commitment;

pub fn test_get_commitment() {
    let config_path = "./tests/config/config.toml";

    let vendor = "unknown";
    let product = "druid";
    let version = "0.22.0";
    let methods = [
        "merkle-tree",
        "sparse-merkle-tree",
        "merkle-patricia-trie",
        "ozks",
    ];

    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        let commitment = get_commitment(vendor, product, version, method, &config);
        let file_prefix = "./tests/proof_data/druid-0.22.0.cdx.json";

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
                crate::upload_sbom::assert_valid_commitment(&commitment, "commitment_ozks");
            }
            _ => panic!("Unknown method: {}", method),
        }
    }
}
