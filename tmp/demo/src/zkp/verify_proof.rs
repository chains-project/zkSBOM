use binary_merkle_tree::MerkleProof;
use sp_core::H256;

use crate::merkle::merkle::{verify_merkle_proof};

pub fn verify_proof(proof: MerkleProof<H256, H256>) -> bool {
    let is_valid = verify_merkle_proof(proof);
    return is_valid;
}
