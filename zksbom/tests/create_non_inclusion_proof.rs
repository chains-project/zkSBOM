use std::fs;
use std::path::Path;
use zksbom::config::load_config_from_file;
use zksbom::method::method_handler::create_proof_no_commitment;

pub fn test_create_non_inclusion_proof() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";
    let expected_sparse_merkle_tree_proof =
        "Proof: 0x4c4ffb51fb48dc909505a3112ea22312367a734f0fdfa185a4ee7c7df1a8022fa8001c35fdff8b2a2ff0eb8e4c2ab28398cc21d6b9af1aecc50a12953b3ffff584531823044f0151fd236596b1be205fa76b19c33dc57904f04f091500260edfe1f39d123ff31b52f049dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c0651fe46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: github.com/chai2010/webp@0.0.0@GO\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x6d4cf5bfb3444c5bbb8ef6561931903d9a547cf7baddc573cec848440a53ac64\nValue: 0x96b0d12d72374a8d61312ba9d73ec9e3587e3ce197337c7e61a6ac39abe2cb1b\n---\nProof: 0x4c4ffc51fc3901306efeccb70b154cf6ee38401413c6a4381a9ec6aec325fa75e78017fa3c5e730734b84da684d6efd8eb5daa5c61bf29f0efa3a8be8e6a0ef3a0d099370951fd877e9dd8a624d73c6e51dc9ea80e286ac395d924bb78d65934dbe4869db0792e4c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c48315680751fe3f85d9274c369071a695efb2b4a4a89c453e9b33ff4f3e67cae612c63b944b0b652b7351c53f6be907f43ef0765c490cc774dbb45822745737837235fa254b125018ca561051d73fd58aba4c5bb234be413752c99df6529c4d6cc5bc3c3391f456\nLeaf: github.com/chai2010/webp@1.1.2@GO\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0xe7e15131be2f4032dc5b01ea48b44763cd0fe36e1f06eb50fe49a3bbc798e9b4\nValue: 0x9a4971a305cc9b82e69a2189f580724a2908e4f17fdd3aa905b13410181b29eb\n---\nProof: 0x4c4ffc51fc236596b1be205fa76b19c33dc57904f04f091500260edfe1f39d123ff31b52f049dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c0651fd48dc909505a3112ea22312367a734f0fdfa185a4ee7c7df1a8022fa8001c35fdff8b2a2ff0eb8e4c2ab28398cc21d6b9af1aecc50a12953b3ffff5845318230c51fe46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: SkiaSharp@2.0.0@NUGET\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0xe5017d0edda244fde5b574dda4849ad7ab9882fe6cdf797138fdb5b1abc42457\nValue: 0x5e3210f82b3931733af38d7aed8b45838f32963f281322e8f5427775c2653827\n---\nProof: 0x4c4ffa51fa3901306efeccb70b154cf6ee38401413c6a4381a9ec6aec325fa75e78017fa3c5e730734b84da684d6efd8eb5daa5c61bf29f0efa3a8be8e6a0ef3a0d09937014f0251fd877e9dd8a624d73c6e51dc9ea80e286ac395d924bb78d65934dbe4869db0792e4c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c48315680751fe3f85d9274c369071a695efb2b4a4a89c453e9b33ff4f3e67cae612c63b944b0b652b7351c53f6be907f43ef0765c490cc774dbb45822745737837235fa254b125018ca561051d73fd58aba4c5bb234be413752c99df6529c4d6cc5bc3c3391f456\nLeaf: electron@27.0.0-beta.1@NPM\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x31b181dfdaacababf9d672db943c0f45664440ea783f350e4500328dcfc2adac\nValue: 0xfcc7c73c74ed6e0b0ae057e590d288315b75930cc4d213a48ca2f937b4e73571\n---\nProof: 0x4c4ffc51fc236596b1be205fa76b19c33dc57904f04f091500260edfe1f39d123ff31b52f049dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c0651fd48dc909505a3112ea22312367a734f0fdfa185a4ee7c7df1a8022fa8001c35fdff8b2a2ff0eb8e4c2ab28398cc21d6b9af1aecc50a12953b3ffff5845318230c51fe46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: electron@26.0.0@NPM\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x4af58fe10684102bc67b8dc4671f897d0e942a14f3fcc7edb0183a9e0fe2275f\nValue: 0x1f11edad901fec5e9d5ac5207fa95196c3464014dad74e19faa1e79c669abd97\n---\nProof: 0x4c4ffd51fd46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150c869a37a0b52cf6f7714d9384d6f421870a4150f33f0c5ba3a9121de3a14bae650d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: electron@25.0.0@NPM\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x020bbed63a650f116d16fd3701d5548ea161e6b517bdce00a576b107727b0c2a\nValue: 0xa6fa9acf417142af3d5f5d464265bba2de14858d091d08e139a3e52fdb5f77a2\n---\nProof: 0x4c4ffd51fd46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150c869a37a0b52cf6f7714d9384d6f421870a4150f33f0c5ba3a9121de3a14bae650d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: electron@24.0.0@NPM\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x5f786400e2db2bcb58c8e7e62a46033777f8ac6fe6d211fd2392f5f28b88883a\nValue: 0x114d86d7bea75e4dfd59bc7ec67384095001027d9a9984e730dbca52d3817948\n---\nProof: 0x4c4ffc51fc48dc909505a3112ea22312367a734f0fdfa185a4ee7c7df1a8022fa8001c35fdff8b2a2ff0eb8e4c2ab28398cc21d6b9af1aecc50a12953b3ffff5845318230c51fd236596b1be205fa76b19c33dc57904f04f091500260edfe1f39d123ff31b52f049dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c0651fe46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f41060150d9662ad64cba1196fcc02777482ae8651c573cb5ea0ecadc3a6f6585036f6b5d\nLeaf: electron@22.0.0@NPM\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: 0x159ba16aa46b6ccf50baf31a1121453c52b0d1b01037619b7941da7df7dd7f74\nValue: 0xbda70753f667cf5ce6b799a41bcabb134cbf72db1c4afc2b3e7f05586dcf442b\n---";
    let expected_merkle_patricia_trie_proof =
        "Proof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: github.com/chai2010/webp@0.0.0@GO\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x10b45de74959139dc32a6c05ae2b67a981aa340c24c14d8777d91a8fc11377d7\nValue: 0x6d4cf5bfb3444c5bbb8ef6561931903d9a547cf7baddc573cec848440a53ac64\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: github.com/chai2010/webp@1.1.2@GO\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x21a2a931a08d8e0ed0634fd1da8754379bf68c13b236df94569f0f0d8c7711d2\nValue: 0xe7e15131be2f4032dc5b01ea48b44763cd0fe36e1f06eb50fe49a3bbc798e9b4\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: SkiaSharp@2.0.0@NUGET\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x024c162c1eb498c00676c3ce6b19e9560b9ae820a5e6c12485bd3b05da67662c\nValue: 0xe5017d0edda244fde5b574dda4849ad7ab9882fe6cdf797138fdb5b1abc42457\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f00807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917;0x7f00035b52c3da44278c1a5787eff2e789ef9e2c8f544148f1488ab34a48f92e7bbf804c41d07ab8a77e1af3fa0f03ec3e37a6fb08251e23b358fd80ae41c483156887\nLeaf: electron@27.0.0-beta.1@NPM\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x5b18ed0055429d78365d292b754afacae1599462757a0348e2430576fb6a6555\nValue: 0x31b181dfdaacababf9d672db943c0f45664440ea783f350e4500328dcfc2adac\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: electron@26.0.0@NPM\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x19a57bbff9d31b7f416cec796912749cfb85c830358f452d50eb23079c17c0e2\nValue: 0x4af58fe10684102bc67b8dc4671f897d0e942a14f3fcc7edb0183a9e0fe2275f\n---\nProof: 0x807020008092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917;0x7f00066244adc13e5a4cc8e4ea8f4d8db10b472e511a4f95a8e0927e57fc67b6166a8049dd318c3e4b6711991299f6bd07c7468bfa9075b63a0a6fed842c10fb990c46\nLeaf: electron@25.0.0@NPM\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x4af037bf2e728024a8fe185a2e2133561ae443c222edd25a4dea7fc2749bed6c\nValue: 0x020bbed63a650f116d16fd3701d5548ea161e6b517bdce00a576b107727b0c2a\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: electron@24.0.0@NPM\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0xbc90326e081e8cd15e75d4785b7816849ac0b9858ae8499498f36664c1f44725\nValue: 0x5f786400e2db2bcb58c8e7e62a46033777f8ac6fe6d211fd2392f5f28b88883a\n---\nProof: 0x807020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f8092fab3c74c2b651f5dc8d260ef3df66e1dd7509d7b0e10df03766e6483ee6ac6807873927dc827e75cbe15e63315547732e4fb5d09bc9916685ffe92bc4dec537880de08f9c99f46e4a216dd86ad5bc36dfe4cb5b5a5149cfd5fc4f35f7080988917\nLeaf: electron@22.0.0@NPM\n# The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\nKey: 0x07cbae1967d3e925bfc1c4bf5f65f2eb36806c855f8db40c42e8fa53ee2d184f\nValue: 0x159ba16aa46b6ccf50baf31a1121453c52b0d1b01037619b7941da7df7dd7f74\n---";
    let expected_ozks_proof = "Dependency: github.com/chai2010/webp@0.0.0@GO;
        Dependency: github.com/chai2010/webp@1.1.2@GO;
        Dependency: SkiaSharp@2.0.0@NUGET;
        Dependency: electron@27.0.0-beta.1@NPM;
        Dependency: electron@26.0.0@NPM;
        Dependency: electron@25.0.0@NPM;
        Dependency: electron@24.0.0@NPM;
        Dependency: electron@22.0.0@NPM;";

    let methods = [
        ("sparse-merkle-tree", expected_sparse_merkle_tree_proof),
        ("merkle-patricia-trie", expected_merkle_patricia_trie_proof),
        ("ozks", expected_ozks_proof),
    ];
    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "CVE-2023-4863";
    let config = load_config_from_file(config_path).unwrap();

    for (method, _) in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
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
        let inclusion_dir = dir.join("non-inclusion-proof");
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
            // Check if actual content contains the dependencies we expected
            for expected_item in expected_proof
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                assert!(
                    actual_content.contains(expected_item),
                    "Proof file for {method} does not contain expected item!\nExpected to find:\n{}\nActual content:\n{}",
                    expected_item, actual_content
                );
            }
        }
    }
}

pub fn test_create_non_inclusion_proof_dependency() {
    let config_path = "./tests/config/config.toml";

    let api_key = "";
    let expected_sparse_merkle_tree_proof =
        "Proof: 0x4c4ffc51fc46c7370a118778f7cbb8bd2569e74894c6aae73e9276ebbbced4ab746480dd49d5676617ec909c3ee5f3fd74810275de40e22f9b5cc3ddde41c51e480f4106014f0150c869a37a0b52cf6f7714d9384d6f421870a4150f33f0c5ba3a9121de3a14bae64f01\n\
        Leaf: foo@0.0.1@foo\n\
        # Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\n\
        Key: 0xe03df719c5056b5295eb6a631fba94aeea536c55dbb1edaa4778647b22b7031d\n\
        Value: 0xadf53a0a54287c8d4a80b5ea4ed3a722f99a9a42a2efffaec33b1b55dda08bab\n\
        ---";
    let expected_merkle_patricia_trie_proof =
        "Proof: 0x805020809fcf3814b08f3c65ba78e201a0dfe0b45a763e167dbc0be7e36db0a8f7608d5f80aa2be7f3a2a9c0f1a40d01ea469309ce4519951cf812b29e00e0b0e35cf77c4e807d58209210e8fd12ba6384b859c68701c9ff2824643714990ba514bd669253cc\n\
        Leaf: foo@0.0.1@foo\n\
        # The Key is the Keccak-256 hash of the dependency string,and the Value is the Keccak-256 hash of the same dependency string, both of which are used asthe key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing theleaf dependency with the hash function.\n\
        Key: 0x7abce335f8277a18775efe9c2aa1dc573a6e8f213481b8803cac9e627cf66b08\n\
        Value: 0xe03df719c5056b5295eb6a631fba94aeea536c55dbb1edaa4778647b22b7031d\n\
        ---";
    let expected_ozks_proof = "Dependency: foo@0.0.1@foo";

    let methods = [
        ("sparse-merkle-tree", expected_sparse_merkle_tree_proof),
        ("merkle-patricia-trie", expected_merkle_patricia_trie_proof),
        ("ozks", expected_ozks_proof),
    ];
    let vendor = "Tom Sorger <sorger@kth.se>";
    let product = "test_openssl";
    let version = "0.1.0";
    let check = "foo@0.0.1@foo";
    let config = load_config_from_file(config_path).unwrap();

    for (method, _) in methods {
        let output = config.app.output.clone();
        create_proof_no_commitment(api_key, method, vendor, product, version, check, &config);

        // Construct original path and target path
        let path = Path::new(&output);
        let dir = path.parent().expect("No parent directory for output file");
        let inclusion_dir = dir.join("non-inclusion-proof");
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
        let inclusion_dir = dir.join("non-inclusion-proof");
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
            // Check if actual content contains the dependencies we expected
            for expected_item in expected_proof
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                assert!(
                    actual_content.contains(expected_item),
                    "Proof file for {method} does not contain expected item!\nExpected to find:\n{}\nActual content:\n{}",
                    expected_item, actual_content
                );
            }
        }
    }
}
