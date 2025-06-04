use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256;
use crate::map_dependencies_vulnerabilities::get_mapping_for_dependencies;
use binary_merkle_tree::{merkle_proof, merkle_root, MerkleProof};
use log::{debug, error};
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str;
use std::time::Instant;

pub struct MerkleRootLeaves {
    pub root: String,
    pub leaves: Vec<String>,
}

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    let hashed_dependencies = hash_h256(dependencies);
    debug!("Hashed dependencies: {:?}", hashed_dependencies);

    // Compute the Merkle root
    let commitment = format!("0x{:x}", merkle_root::<BlakeTwo256, _>(hashed_dependencies));
    debug!("Merkle Tree Commitment: {:?}", commitment);

    return commitment;
}

fn generate_proof(root: String, dependency: String) -> (MerkleProof<H256, H256>, String) {
    let dependency_entry = get_dependencies(root.clone(), "merkle-tree");

    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    debug!("dependencies: {:?}", dependencies);
    debug!("root merkle: {:?}", &root);

    let index = if let Some(found_index) = dependencies.iter().position(|&leaf| leaf == dependency)
    {
        debug!("Dependency found at index {}", found_index);
        found_index as u32
    } else {
        error!("{} not found", dependency);
        panic!("Dependency not found");
    };

    // Hash dependencies
    let hashed_leaves_list = hash_h256(dependencies);

    debug!("Hashed leaves: {:?}", hashed_leaves_list);

    let now = Instant::now();
    let proof: MerkleProof<H256, H256> =
        merkle_proof::<BlakeTwo256, _, _>(hashed_leaves_list, index);
    let elapsed = now.elapsed();

    debug!("Proof: {:?}", proof);

    return (proof, elapsed.as_nanos().to_string());
}

pub fn create_proof(commitment: &str, vulnerability: &str) -> String {
    let dependency_entry = get_dependencies(commitment.to_string(), "merkle-tree");
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone());

    for dep in dependencies {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);
        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&vulnerability.to_string()) {
                debug!("Dependency: {} is vulnerable to: {}", dep, vulnerability);

                let (proof, elapsed) = generate_proof(commitment.to_string(), dep.to_string());

                print_proof(proof, dep.to_string());

                return elapsed;
            }
        }
    }
    return "".to_string();
}

fn print_proof(proof: MerkleProof<H256, H256>, dependency: String) {
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
