use crate::method::merkle_patricia_trie::verify as verify_merkle_patricia_trie;
use crate::method::merkle_tree::verify as verify_merkle_tree;
use crate::method::sparse_merkle_tree::verify as verify_sparse_merkle_tree;
use log::debug;

pub fn verify(commitment: &str, proof_path: &str, method: &str) -> bool {
    match method {
        "merkle-tree" => {
            let is_valid = verify_merkle_tree(commitment, proof_path);
            debug!("Merkle Tree proof is valid: {}", is_valid);
            return is_valid;
        }
        "sparse-merkle-tree" => {
            let is_valid = verify_sparse_merkle_tree(commitment, proof_path);
            debug!("Merkle Tree proof is valid: {}", is_valid);
            return is_valid;
        }
        "merkle-patricia-trie" => {
            let is_valid = verify_merkle_patricia_trie(commitment, proof_path);
            debug!("Merkle Patricia Trie proof is valid: {}", is_valid);
            return is_valid;
        }
        _ => {
            panic!("Unknown method: {}", method);
        }
    }
}
