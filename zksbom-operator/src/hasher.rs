use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::str;

pub fn hash_h256(dependencies_clear_text: Vec<&str>) -> Vec<H256> {
    // Convert string leaves to H256 hashes
    return dependencies_clear_text
        .iter()
        .map(|leaf| H256::from_slice(&BlakeTwo256::hash(leaf.as_bytes()).0))
        .collect();
}

pub fn hash_h256_kv(dependencies_clear_text: Vec<&str>) -> Vec<(H256, H256)> {
    let mut hash_kv: Vec<(H256, H256)> = Vec::new();
    for dependency_clear_text in dependencies_clear_text {
        let value = H256::from_slice(&BlakeTwo256::hash(dependency_clear_text.as_bytes()).0);
        // Key is hash(dependency_clear_text + value)
        let mut key_bytes = dependency_clear_text.as_bytes().to_vec(); // Convert to a mutable Vec<u8>
        key_bytes.extend_from_slice(value.as_bytes()); // Use extend_from_slice on the Vec
        let key = H256::from_slice(&BlakeTwo256::hash(&key_bytes).0); // Hash the combined Vec
        hash_kv.push((key, value));
    }
    return hash_kv;
}
