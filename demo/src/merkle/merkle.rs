use binary_merkle_tree::{merkle_root, merkle_proof, verify_proof, MerkleProof};
use log::debug;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;


pub fn get_root(leaves: Vec<String>) -> H256 {
    // Convert string leaves to H256 hashes
    let hashed_leaves: Vec<H256> = leaves.iter()
        .map(|leaf| H256::from_slice(&BlakeTwo256::hash(leaf.as_bytes()).0))
        .collect();

    // Compute the Merkle root
    let root = merkle_root::<BlakeTwo256, _>(&hashed_leaves);

    debug!("Merkle root: {:?}", root);
    return root;
}

pub fn generate_merkle_proof(root: H256, vulnerability: String) -> MerkleProof<H256, H256> {
    // TODO: Get the leaves from the database
    let hashed_leaves: Vec<H256> = vec![];

    let proof: MerkleProof<H256, H256> = merkle_proof::<BlakeTwo256, _, _>(hashed_leaves, 1);
    // println!("Proof: {:?}", proof);

    debug!("root: {:?}", proof.root);
    debug!("proof: {:?}", proof.proof);
    debug!("number_of_leaves: {:?}", proof.number_of_leaves);
    debug!("leaf_index: {:?}", proof.leaf_index);
    debug!("leaf: {:?}", proof.leaf);

    return proof;
}

pub fn verify_merkle_proof(proof: MerkleProof<H256, H256>) -> bool {
    let is_valid = verify_proof::<BlakeTwo256, Vec<H256>, &_>(
        &proof.root,
        proof.proof,
        proof.number_of_leaves,
        proof.leaf_index,
        &proof.leaf
    );

    debug!("Proof is valid: {}", is_valid);
    return is_valid;
}