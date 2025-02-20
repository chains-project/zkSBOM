use log::info;
use sp_core::H256;
use crate::zkp::generate_proof::generate_proof;
use binary_merkle_tree::MerkleProof;

// Function for the "get-zk-proof" command
pub fn get_zk_proof(api_key: &str, commitment: &str, vulnerability: &str) {
    info!(
        "Getting ZK proof for API key: {}, commitment: {}, vulnerability: {}",
        api_key, commitment, vulnerability
    );
    // Add your logic here

    let commitment_h256 = H256::from_slice(&hex::decode(commitment).expect("Invalid hex string"));
    let proof = generate_proof(commitment_h256, vulnerability.to_string());
    info!("Proof: {:?}", proof);
}
