use binary_merkle_tree::{merkle_root, merkle_proof, verify_proof, MerkleProof};
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;

fn main() {
    merkle();
}

fn merkle() {
    // User input -- cannot be changed
    let t_leaves = vec!["a", "b", "c", "d", "e", "f", "g", "h"];
        
    // Convert string leaves to H256 hashes
    let hashed_leaves: Vec<H256> = t_leaves.iter()
        .map(|leaf| H256::from_slice(&BlakeTwo256::hash(leaf.as_bytes()).0))
        .collect();

    // Compute the Merkle root
    let t_root = merkle_root::<BlakeTwo256, _>(&hashed_leaves);

    println!("Merkle root: {:?}", t_root);


    // Generate a Merkle proof for the leaf "b" (index starts at 0; so we need index 1)
    let proof: MerkleProof<H256, H256> = merkle_proof::<BlakeTwo256, _, _>(hashed_leaves, 1);
    // println!("Proof: {:?}", proof);

    println!("root: {:?}", proof.root);
    println!("proof: {:?}", proof.proof);
    println!("number_of_leaves: {:?}", proof.number_of_leaves);
    println!("leaf_index: {:?}", proof.leaf_index);
    println!("leaf: {:?}", proof.leaf);
    

    // Verify the proof
    let is_valid = verify_proof::<BlakeTwo256, Vec<H256>, &_>(
        &proof.root,
        proof.proof,
        proof.number_of_leaves,
        proof.leaf_index,
        &proof.leaf
    );

    println!("Proof is valid: {}", is_valid);
}
