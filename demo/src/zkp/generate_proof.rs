
use binary_merkle_tree::MerkleProof;
use sp_core::H256;

use crate::merkle::merkle::{generate_merkle_proof};

pub fn generate_proof(root: H256, vulnerability: String) -> MerkleProof<H256, H256> {
    let proof = generate_merkle_proof(root, vulnerability);
    return proof;
}
