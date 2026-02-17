use zksbom_verifier::config::load_config_from_file;
use zksbom_verifier::method::method_handler::verify;

#[test]
pub fn test_non_inclusion_proof() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        ("sparse-merkle-tree", "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51"),
        ("merkle-patricia-trie", "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633"),
        ("ozks", "700000001000000000000a002e002800240004000a0000000035f8eb542169da36c66dd76b4caaa892d1a81cfda761f644cb4034fca4d1701000000001000000000006000800040006000000040000002000000087a1de117db5bcf3b19fb2bb0375eb79b7c1c07e943138b1dbeb4f96d78ba6ad")
    ];

    for (method, commitment) in methods {
        let proof_path = format!("./tests/proofs/non-inclusion-proof/{method}-proof.txt");
        assert!(verify(commitment, &proof_path, method, &config.app));
    }
}

#[test]
pub fn test_non_inclusion_proof_dependency() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        ("sparse-merkle-tree", "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51"),
        ("merkle-patricia-trie", "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633"),
        ("ozks", "700000001000000000000a002e002800240004000a0000001c6e39a777cac91222f2d19908e8eaf913cfca101fdee3ad842a1859fd036859100000000100000000000600080004000600000004000000200000009c81e1d6df376eb783685d9b78b0041ecbbb9c15c1e2e3cb5a1c6846acb33a1f")
    ];

    for (method, commitment) in methods {
        let proof_path = format!("./tests/proofs/non-inclusion-proof/{method}-proof-dep.txt");
        assert!(verify(commitment, &proof_path, method, &config.app));
    }
}
