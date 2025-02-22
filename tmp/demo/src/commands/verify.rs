use binary_merkle_tree::MerkleProof;
use log::info;
use sp_core::H256;
use crate::zkp::verify_proof::verify_proof;

// Function for the "verify" command
pub fn verify(proof: MerkleProof<H256, H256>) -> bool {
    let is_valid = verify_proof(proof);
    info!("Proof is valid: {}", is_valid);
    return is_valid;
}
