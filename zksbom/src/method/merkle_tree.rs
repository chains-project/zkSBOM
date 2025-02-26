use crate::database::db_dependency::get_dependencies;
use binary_merkle_tree::{merkle_proof, merkle_root, MerkleProof};
use hex;
use log::debug;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;

pub struct MerkleRootLeaves {
    pub root: String,
    pub leaves: Vec<String>,
}

pub fn create_commitment(dependencies: Vec<&str>) -> MerkleRootLeaves {
    debug!("Dependencies: {:?}", dependencies);

    // Convert string leaves to H256 hashes
    let hashed_leaves: Vec<H256> = dependencies
        .iter()
        .map(|leaf| H256::from_slice(&BlakeTwo256::hash(leaf.as_bytes()).0))
        .collect();

    // Compute the Merkle root
    let root = merkle_root::<BlakeTwo256, _>(&hashed_leaves);

    debug!("Merkle root: {:?}", root);
    let root_string = format!("0x{:x}", root); // Lowercase hex string

    debug!("Leaves: {:?}", hashed_leaves);

    return MerkleRootLeaves {
        root: root_string,
        leaves: hashed_leaves.iter().map(|v| format!("0x{:x}", v)).collect(), // Lowercase
    };
}

pub fn generate_proof(root: String, dependency: String) -> MerkleProof<H256, H256> {
    // 1. Get the hashed leaves from the database
    let hashed_leaves = get_dependencies(root).dependencies;
    let hashed_leaves_list: Vec<&str> = hashed_leaves.split(",").collect();
    debug!("Hashed leaves: {:?}", hashed_leaves_list);

    // 2. Hash the dependency
    let hashed_dependency = H256::from_slice(&BlakeTwo256::hash(dependency.as_bytes()).0);
    debug!("Hashed dependency: {:?}", hashed_dependency);
    let dependency_string = format!("0x{:x}", hashed_dependency); // Lowercase hex string

    // TODO: fix to check what to do when dependency is not found
    let index = 0;
    if let Some(index) = hashed_leaves_list
        .iter()
        .position(|&leaf| leaf == dependency_string)
    {
        debug!("Dependency found at index {}", index);
    } else {
        debug!("Dependency not found");
    }

    // 3. Generate the proof
    let hashed_leaves: Vec<H256> = hashed_leaves_list
        .iter()
        .map(|leaf| {
            H256::from_slice(&hex::decode(leaf.trim_start_matches("0x")).expect("Decoding failed"))
        })
        .collect();

    debug!("Hashed leaves: {:?}", hashed_leaves);

    let proof: MerkleProof<H256, H256> = merkle_proof::<BlakeTwo256, _, _>(hashed_leaves, index);
    debug!("Proof: {:?}", proof);

    return proof;
}
