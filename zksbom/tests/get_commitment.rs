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
            "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d",
        ),
        (
            "sparse-merkle-tree",
            "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51",
        ),
        (
            "merkle-patricia-trie",
            "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633",
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
