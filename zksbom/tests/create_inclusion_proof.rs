use std::fs;
use std::path::Path;
use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::create_proof_no_commitment;

pub fn test_create_inclusion_proof() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";
    let expected_merkle_tree_proof =
        "Proof: [0x0f09337a009a274fa07df1cc62b7b8dbb871df8f52155eac97f13c78318020cc, 0xe83c977e5cbbb435c59239d02467b046a4484330ca591fc45aedc954ef804a7c, 0x30a2369d7b1265ce289b5ac125604fe7f534c51e52b3a63636d9f6f3b3f04d7b]\n\
        Number of Leaves: 6\n\
        Leaf Index: 3\n\
        Leaf: openssl@RUST\n\
        Leaf Hash (Each dependency is hashed using Substrate's BlakeTwo256 hasher (an unkeyed Blake2b hash truncated to 256 bits), then stored as an H256.): 0x4c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c483156887";
    let expected_sparse_merkle_tree_proof =
        "Proof: 0x4c4ffd51fd3901306efeccb70b154cf6ee38401413c6a4381a9ec6aec325fa75e78017fa3c5e730734b84da684d6efd8eb5daa5c61bf29f0efa3a8be8e6a0ef3a0d099370951fe3f85d9274c369071a695efb2b4a4a89c453e9b33ff4f3e67cae612c63b944b0b652b7351c53f6be907f43ef0765c490cc774dbb45822745737837235fa254b125018ca561051d73fd58aba4c5bb234be413752c99df6529c4d6cc5bc3c3391f456\n\
        Leaf: openssl@RUST\n\
        # Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\n\
        Key: 0x4c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c483156887\n\
        Value: 0x535447971ebb88e11b339d847807aba97143960252af031d14ef0bd3176ab065";
    let expected_merkle_patricia_trie_proof =
        "Proof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f00807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917;0x7f00035b52c3da44278c1a5787eff2e789ef9e2c8f544148f1488ab34a48f92e7bbf00\n\
        Leaf: openssl@RUST\n\
        # The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\n\
        Key: 0x535b52c3da44278c1a5787eff2e789ef9e2c8f544148f1488ab34a48f92e7bbf\n\
        Value: 0x4c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c483156887";
    let expected_ozks_proof = "Dependency: openssl@RUST";

    let methods = [
        ("merkle-tree", expected_merkle_tree_proof),
        ("sparse-merkle-tree", expected_sparse_merkle_tree_proof),
        ("merkle-patricia-trie", expected_merkle_patricia_trie_proof),
        ("ozks", expected_ozks_proof),
    ];
    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "CVE-2025-24898";
    let config = load_config_from_file(config_path).unwrap();

    for (method, _) in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Rename/move the proof file to avoid overwriting
        fs::rename(path, &new_path)
            .unwrap_or_else(|e| panic!("Failed to rename proof file for {method}: {e}"));
    }

    // Remove last file from the tests:
    let dir = Path::new(&config.app.output)
        .parent()
        .expect("No parent dir");

    // Iterate over entries in the directory
    for entry in fs::read_dir(dir).expect("Failed to read dir") {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        // Remove only files, not directories
        if path.is_file() {
            let _ = fs::remove_file(&path);
        }
    }

    // Verify proof files
    for (method, expected_proof) in methods {
        let output = config.app.output.clone();

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Compare file with expected content
        if method != "ozks" {
            let actual_content = fs::read_to_string(&new_path)
                .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
            assert_eq!(
                actual_content.trim(),
                expected_proof.trim(),
                "Proof file for {method} does not match expected content!"
            );
        } else {
            let actual_content = fs::read_to_string(&new_path)
                .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
            // Check if actual content contains the dependency
            assert!(
                actual_content.contains(expected_proof),
                "Proof file for {method} does not contain expected content!\nExpected to find:\n{}\nActual content:\n{}",
                expected_proof, actual_content
            );
        }
    }
}

pub fn test_create_inclusion_proof_dependency() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";
    let expected_merkle_tree_proof =
        "Proof: [0x5454d661b59b7fed79f1b058f898599f88a62f4a1b9fa40826a426edd50fe0f1, 0x0f09337a009a274fa07df1cc62b7b8dbb871df8f52155eac97f13c78318020cc]\n\
        Number of Leaves: 3\n\
        Leaf Index: 0\n\
        Leaf: openssl@0.10.1@RUST\n\
        Leaf Hash (Each dependency is hashed using Substrate's BlakeTwo256 hasher (an unkeyed Blake2b hash truncated to 256 bits), then stored as an H256.): 0x49dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c46";
    let expected_sparse_merkle_tree_proof =
        "Proof: 0x4c4ffd51fd48dc909505a3112ea22312367a734f0fdfa185a4ee7c7df1a8022fa8001c35fdff8b2a2ff0eb8e4c2ab28398cc21d6b9af1aecc50a12953b3ffff5845318230c51fe46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f4106014f01\n\
        Leaf: openssl@0.10.1@RUST\n\
        # Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\n\
        Key: 0x49dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c46\n\
        Value: 0x0f8a714a5e59649722752391b91a28b05d0e85e6a0e67ebe87bb4d892c6ca060\n\
        ---";
    let expected_merkle_patricia_trie_proof =
        "Proof: 0x8050200080aa2be7f3a2a9c0f1a40d01ea469309ce4519951cf812b29e00e0b0e35cf77c4e807d58209210e8fd12ba6384b859c68701c9ff2824643714990ba514bd669253cc;0x7f00066244adc13e5a4cc8e4ea8f4d8db10b472e511a4f95a8e0927e57fc67b6166a00\n\
        Leaf: openssl@0.10.1@RUST\n\
        # The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\n\
        Key: 0x466244adc13e5a4cc8e4ea8f4d8db10b472e511a4f95a8e0927e57fc67b6166a\n\
        Value: 0x49dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c46";
    let expected_ozks_proof = "Dependency: openssl@0.10.1@RUST";

    let methods = [
        ("merkle-tree", expected_merkle_tree_proof),
        ("sparse-merkle-tree", expected_sparse_merkle_tree_proof),
        ("merkle-patricia-trie", expected_merkle_patricia_trie_proof),
        ("ozks", expected_ozks_proof),
    ];
    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "openssl@0.10.1@RUST";
    let config = load_config_from_file(config_path).unwrap();

    for (method, _) in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof-dep.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Rename/move the proof file to avoid overwriting
        fs::rename(path, &new_path)
            .unwrap_or_else(|e| panic!("Failed to rename proof file for {method}: {e}"));
    }

    // Remove last file from the tests:
    let dir = Path::new(&config.app.output)
        .parent()
        .expect("No parent dir");

    // Iterate over entries in the directory
    for entry in fs::read_dir(dir).expect("Failed to read dir") {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        // Remove only files, not directories
        if path.is_file() {
            let _ = fs::remove_file(&path);
        }
    }

    // Verify proof files
    for (method, expected_proof) in methods {
        let output = config.app.output.clone();

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("inclusion-proof");
        fs::create_dir_all(&inclusion_dir).unwrap();
        let new_filename = format!("{method}-proof-dep.txt");
        let new_path = inclusion_dir.join(&new_filename);

        // Compare file with expected content
        if method != "ozks" {
            let actual_content = fs::read_to_string(&new_path)
                .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
            assert_eq!(
                actual_content.trim(),
                expected_proof.trim(),
                "Proof file for {method} does not match expected content!"
            );
        } else {
            let actual_content = fs::read_to_string(&new_path)
                .unwrap_or_else(|e| panic!("Failed to read proof file for {method}: {e}"));
            // Check if actual content contains the dependency
            assert!(
                actual_content.contains(expected_proof),
                "Proof file for {method} does not contain expected content!\nExpected to find:\n{}\nActual content:\n{}",
                expected_proof, actual_content
            );
        }
    }
}
