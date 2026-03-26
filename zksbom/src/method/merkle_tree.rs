use crate::hasher::hash_h256;
use binary_merkle_tree::{merkle_proof, merkle_root, MerkleProof};
use log::{debug, error};
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;
use std::time::Instant;

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    let hashed_dependencies = hash_h256(dependencies);
    debug!("Hashed dependencies: {:?}", hashed_dependencies);

    let commitment = format!("0x{:x}", merkle_root::<BlakeTwo256, _>(hashed_dependencies));
    debug!("Merkle Tree Commitment: {:?}", commitment);
    commitment
}

pub fn generate_formatted_proof(
    _commitment: &str,
    dependencies: Vec<&str>,
    dependency: &str,
) -> (String, String) {
    let index = if let Some(found_index) = dependencies.iter().position(|&leaf| leaf == dependency)
    {
        found_index as u32
    } else {
        error!("{} not found", dependency);
        panic!("Dependency not found");
    };

    let hashed_leaves_list = hash_h256(dependencies);
    let now = Instant::now();
    let proof: MerkleProof<H256, H256> =
        merkle_proof::<BlakeTwo256, _, _>(hashed_leaves_list, index);
    let elapsed = now.elapsed().as_nanos().to_string();

    let formatted_payload = format!(
        "Proof: {:?}\nNumber of Leaves: {:?}\nLeaf Index: {:?}\nLeaf: {}\nLeaf Hash (Each dependency is hashed using Substrate's BlakeTwo256 hasher (an unkeyed Blake2b hash truncated to 256 bits), then stored as an H256.): {:?}",
        proof.proof, proof.number_of_leaves, proof.leaf_index, dependency, proof.leaf
    );

    (formatted_payload, elapsed)
}
