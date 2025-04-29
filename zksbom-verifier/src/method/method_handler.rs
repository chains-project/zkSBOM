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
        "zkp" => {}
        _ => {
            panic!("Unknown method: {}", method);
        }
    }
    return false;
}
