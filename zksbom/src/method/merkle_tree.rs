use log::{debug, info, error};

use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;

use binary_merkle_tree::{merkle_root, merkle_proof, verify_proof, MerkleProof};

pub struct MerkleRootLeaves {
    pub root: String,
    pub leaves: Vec<String>,
}

pub fn create_commitment(vulnerabilities: Vec<&str>) -> MerkleRootLeaves {
    debug!("Vulnerabilities: {:?}", vulnerabilities);

     // Convert string leaves to H256 hashes
     let hashed_leaves: Vec<H256> = vulnerabilities.iter()
     .map(|leaf| H256::from_slice(&BlakeTwo256::hash(leaf.as_bytes()).0))
     .collect();

     // Compute the Merkle root
     let root = merkle_root::<BlakeTwo256, _>(&hashed_leaves);

     debug!("Merkle root: {:?}", root);
     let root_string = format!("{:x}", root); // Lowercase hex string
     debug!("Merkle root string: {}", root_string);

     error!("Leaves: {:?}", hashed_leaves);

     return MerkleRootLeaves {
         root: root_string,
         leaves: hashed_leaves.iter().map(|v| format!("{:x}", v)).collect(), // Lowercase
     };
}

pub fn generate_proof(root: String, vulnerability: String) 
// -> MerkleProof<H256, H256>
{

}
