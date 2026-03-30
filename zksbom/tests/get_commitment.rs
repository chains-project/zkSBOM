use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::get_commitment;

pub fn test_get_commitment() {
    let config_path = "./tests/config/config.toml";

    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let methods = [
        "merkle-tree",
        "sparse-merkle-tree",
        "merkle-patricia-trie",
        "ozks",
    ];

    let config = load_config_from_file(config_path).unwrap();

    for method in methods {
        let commitment = get_commitment(vendor, product, version, method, &config);
        assert_valid_commitment(&commitment, method);
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
