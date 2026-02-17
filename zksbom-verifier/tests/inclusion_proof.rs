use zksbom_verifier::config::load_config_from_file;
use zksbom_verifier::method::method_handler::verify;

#[test]
pub fn test_inclusion_proof() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        ("merkle-tree", "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d"),
        ("sparse-merkle-tree", "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51"),
        ("merkle-patricia-trie", "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633"),
        ("ozks", "700000001000000000000a002e002800240004000a000000ccd47f6f6bd47186e33a03359ed955e3ea0fefe37a7f2ba7b81d4dd41a538c7910000000010000000000060008000400060000000400000020000000a2808380a192ba236a1a6779777c266a783f40653314982369ea471b299a38f8")

    ];

    for (method, commitment) in methods {
        let proof_path = format!("./tests/proofs/inclusion-proof/{method}-proof.txt");
        assert!(verify(commitment, &proof_path, method, &config.app));
    }
}

#[test]
pub fn test_inclusion_proof_dependency() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        ("merkle-tree", "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d"),
        ("sparse-merkle-tree", "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51"),
        ("merkle-patricia-trie", "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633"),
        ("ozks", "700000001000000000000a002e002800240004000a0000001c6e39a777cac91222f2d19908e8eaf913cfca101fdee3ad842a1859fd036859100000000100000000000600080004000600000004000000200000009c81e1d6df376eb783685d9b78b0041ecbbb9c15c1e2e3cb5a1c6846acb33a1f")

    ];

    for (method, commitment) in methods {
        let proof_path = format!("./tests/proofs/inclusion-proof/{method}-proof-dep.txt");
        assert!(verify(commitment, &proof_path, method, &config.app));
    }
}
