use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256;
use crate::map_dependencies_vulnerabilities::map_dependencies_vulnerabilities;
use binary_merkle_tree::{merkle_proof, merkle_root, MerkleProof};
use log::{debug, error};
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str;

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    let commitment = "".to_string();

    return commitment;
}

fn generate_proof(root: String, dependency: String) -> String {
    let proof = "".to_string();

    return proof;
}

pub fn create_proof(commitment: &str, vulnerability: &str) {}

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

    // if let Err(e) = writeln!(file, "Proof: {:?}", proof.proof) {
    //     error!("Error writing to file: {}", e);
    //     return;
    // }

    println!("Proof written to: {}", output_path);
}
