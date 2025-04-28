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
