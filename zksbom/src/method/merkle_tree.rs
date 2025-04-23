use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::map_dependencies_vulnerabilities::map_dependencies_vulnerabilities;
use binary_merkle_tree::{merkle_proof, merkle_root, MerkleProof};
use hex;
use log::{debug, error};
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str;

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

fn generate_proof(root: String, dependency: String) -> MerkleProof<H256, H256> {
    // 1. Get the hashed leaves from the database
    let hashed_leaves = get_dependencies(root).dependencies;
    let hashed_leaves_list: Vec<&str> = hashed_leaves.split(",").collect();
    debug!("Hashed leaves: {:?}", hashed_leaves_list);

    // 2. Hash the dependency
    let hashed_dependency = H256::from_slice(&BlakeTwo256::hash(dependency.as_bytes()).0);
    debug!("Hashed dependency: {:?}", hashed_dependency);
    let dependency_string = format!("0x{:x}", hashed_dependency); // Lowercase hex string

    let index = if let Some(found_index) = hashed_leaves_list
        .iter()
        .position(|&leaf| leaf == dependency_string)
    {
        debug!("Dependency found at index {}", found_index);
        found_index as u32
    } else {
        panic!("Dependency not found");
    };

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

pub fn create_merkle_proof(commitment: &str, vulnerability: &str) {
    let dep_vul_map = map_dependencies_vulnerabilities(commitment.to_string());
    for (key, values) in &dep_vul_map {
        debug!("Dependency: {}, Vulnerabilities: {:?}", key, values);
    }

    for (key, values) in &dep_vul_map {
        if values.contains(&vulnerability.to_string()) {
            debug!("Dependency: {} is vulnerable to: {}", key, vulnerability);

            let proof: MerkleProof<H256, H256> = generate_proof(commitment.to_string(), key.to_string());

            print_merkle_proof(proof, key.to_string());

            break; // Break the loop after finding the first match
        }
    }
}

fn print_merkle_proof(proof: MerkleProof<H256, H256>, dependency: String) {
    let config = load_config().unwrap();
    let output_path = config.app.output;

    let path = Path::new(&output_path);
    if let Some(parent) = path.parent() {
        if let Err(e) = create_dir_all(parent) {
            error!("Error creating directory: {}", e);
            return;
        }
    }

    let mut file = match File::create(&output_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error creating file: {}", e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "Proof: {:?}", proof.proof) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Number of Leaves: {:?}", proof.number_of_leaves) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Leaf Index: {:?}", proof.leaf_index) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Leaf: {}", dependency) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Leaf Hash (Each dependency is hashed using Substrate's BlakeTwo256 hasher (an unkeyed Blake2b hash truncated to 256 bits), then stored as an H256.): {:?} ", proof.leaf) {
        error!("Error writing to file: {}", e);
        return;
    }
    

    println!("Proof written to: {}", output_path);
}
