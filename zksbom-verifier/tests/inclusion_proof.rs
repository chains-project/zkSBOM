use std::fs;
use zksbom_verifier::config::load_config_from_file;
use zksbom_verifier::method::method_handler::verify;

#[test]
pub fn test_inclusion_proof() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        // ("merkle-tree", "mt"),
        // ("sparse-merkle-tree", "smt"),
        // ("merkle-patricia-trie", "mpt"),
        ("ozks", "ozks"),
    ];

    for (method, short_handle) in methods {
        let proof_path =
            format!("./tests/proof-data/strapi.cdx.json/{short_handle}-inclusion-proof.txt");
        let commitment_path =
            format!("./tests/proof-data/strapi.cdx.json/{short_handle}-commitment.txt");
        let commitment =
            fs::read_to_string(commitment_path).expect("Should have been able to read the file");

        assert!(verify(
            commitment.as_str(),
            &proof_path,
            method,
            &config.app
        ));
    }
}

#[test]
pub fn test_inclusion_proof_dependency() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        // ("merkle-tree", "mt"),
        // ("sparse-merkle-tree", "smt"),
        // ("merkle-patricia-trie", "mpt"),
        ("ozks", "ozks"),
    ];

    for (method, short_handle) in methods {
        let proof_path =
            format!("./tests/proof-data/strapi.cdx.json/{short_handle}-inclusion-proof-dep.txt");
        let commitment_path =
            format!("./tests/proof-data/strapi.cdx.json/{short_handle}-commitment.txt");
        let commitment =
            fs::read_to_string(commitment_path).expect("Should have been able to read the file");

        assert!(verify(
            commitment.as_str(),
            &proof_path,
            method,
            &config.app
        ));
    }
}
