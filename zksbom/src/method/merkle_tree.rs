use log::{debug, info, error};

use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;

use binary_merkle_tree::{merkle_root, merkle_proof, verify_proof, MerkleProof};

use crate::database::db_vulnerability::{VulnerabilityDbEntry, init_db_vulnerability, insert_vulnerability, get_vulnerabilities, delete_db_vulnerability};


use hex;



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
     let root_string = format!("0x{:x}", root); // Lowercase hex string

     debug!("Leaves: {:?}", hashed_leaves);

     return MerkleRootLeaves {
         root: root_string,
         leaves: hashed_leaves.iter().map(|v| format!("0x{:x}", v)).collect(), // Lowercase
     };
}

pub fn generate_proof(root: String, vulnerability: String) -> MerkleProof<H256, H256> {
    error!("Implement generate_proof");
    error!("Root: {}", root);
    error!("Vulnerability: {}", vulnerability);

    // 1. Get the hashed leaves from the database
    let hashed_leaves = get_vulnerabilities(root).vulnerabilities;
    let hashed_leaves_list: Vec<&str> = hashed_leaves.split(",").collect();
    debug!("Hashed leaves: {:?}", hashed_leaves_list);

    // 2. Hash the vulnerability
    let hashed_vulnerability = H256::from_slice(&BlakeTwo256::hash(vulnerability.as_bytes()).0);
    debug!("Hashed vulnerability: {:?}", hashed_vulnerability);
    let vulnerability_string = format!("0x{:x}", hashed_vulnerability); // Lowercase hex string


    // TODO: fix to check what to do when vulnerability is not found
    let index = 0;
    if let Some(index) = hashed_leaves_list.iter().position(|&leaf| leaf == vulnerability_string) {
        debug!("Vulnerability found at index {}", index);
    } else {
        debug!("Vulnerability not found");
    }

    // 3. Generate the proof
    let hashed_leaves: Vec<H256> = hashed_leaves_list.iter()
        .map(|leaf| H256::from_slice(&hex::decode(leaf.trim_start_matches("0x")).expect("Decoding failed")))
        .collect();

    debug!("Hashed leaves: {:?}", hashed_leaves);

    let proof: MerkleProof<H256, H256> = merkle_proof::<BlakeTwo256, _, _>(hashed_leaves, index);
    debug!("Proof: {:?}", proof);

    return proof;
}
