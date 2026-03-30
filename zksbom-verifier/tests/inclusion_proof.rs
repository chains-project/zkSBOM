use zksbom_verifier::config::load_config_from_file;
use zksbom_verifier::method::method_handler::verify;

#[test]
pub fn test_inclusion_proof() {
    let config =
        load_config_from_file("./tests/config/config.toml").expect("Failed to load config");

    let methods = [
        ("merkle-tree", "0x147371669a559c8f9daaccee3d98f37d8850377882d2fd6e4d94079c861e7ae4"),
        ("sparse-merkle-tree", "0x949650e05725a7dd3415982d89315dcbc3f5bac994a97b4c1b60ac7c0695c4a7"),
        ("merkle-patricia-trie", "0xf67ab4fdac9fa1a5db9c0c42d6b95517fbf24cc9108d7a8156e805841f9f6e1a"),
        ("ozks", "700000001000000000000a002e002800240004000a00000012b3126e9f052192851061d14420e2ff8ca009e4fa894424503fc0fc8fa270b01000000001000000000006000800040006000000040000002000000053778d5194d5e01a725fffd0c1da9a6160fec07438f3b8922d1cacc49333fe60")

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
        ("merkle-tree", "0x147371669a559c8f9daaccee3d98f37d8850377882d2fd6e4d94079c861e7ae4"),
        ("sparse-merkle-tree", "0x949650e05725a7dd3415982d89315dcbc3f5bac994a97b4c1b60ac7c0695c4a7"),
        ("merkle-patricia-trie", "0xf67ab4fdac9fa1a5db9c0c42d6b95517fbf24cc9108d7a8156e805841f9f6e1a"),
        ("ozks", "700000001000000000000a002e002800240004000a00000012b3126e9f052192851061d14420e2ff8ca009e4fa894424503fc0fc8fa270b01000000001000000000006000800040006000000040000002000000053778d5194d5e01a725fffd0c1da9a6160fec07438f3b8922d1cacc49333fe60")
    ];

    for (method, commitment) in methods {
        let proof_path = format!("./tests/proofs/inclusion-proof/{method}-proof-dep.txt");
        assert!(verify(commitment, &proof_path, method, &config.app));
    }
}
