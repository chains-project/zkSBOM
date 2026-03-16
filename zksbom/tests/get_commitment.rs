use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::get_commitment;

pub fn test_get_commitment() {
    let config_path = "./tests/config/config.toml";

    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let methods = [
        (
            "merkle-tree",
            "0x147371669a559c8f9daaccee3d98f37d8850377882d2fd6e4d94079c861e7ae4",
        ),
        (
            "sparse-merkle-tree",
            "0x949650e05725a7dd3415982d89315dcbc3f5bac994a97b4c1b60ac7c0695c4a7",
        ),
        (
            "merkle-patricia-trie",
            "0xf67ab4fdac9fa1a5db9c0c42d6b95517fbf24cc9108d7a8156e805841f9f6e1a",
        ),
        ("ozks", ""),
    ];
    let config = load_config_from_file(config_path).unwrap();

    for (method, expetced_commitment) in methods {
        let commitment = get_commitment(vendor, product, version, method, &config);
        if method != "ozks" {
            assert_eq!(expetced_commitment, commitment);
        } else {
            assert!(
                commitment.chars().any(|c| c != '0'),
                "oZKS commitment is all zeroes!"
            );
        }
    }
}
