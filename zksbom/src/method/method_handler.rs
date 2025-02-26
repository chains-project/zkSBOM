use crate::config::load_config;
use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_tree::{create_commitment as create_merkle_commitment, generate_proof};
use binary_merkle_tree::MerkleProof;
use log::{debug, error, info};
use sp_core::H256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

pub fn create_commitment(dependencies: Vec<&str>) -> (String, Vec<String>) {
    // TODO: Implement handling for different methods
    let merkle_root_leaves = create_merkle_commitment(dependencies);
    let commitment = merkle_root_leaves.root;
    let dependencies = merkle_root_leaves.leaves;

    return (commitment, dependencies);
}

pub fn get_commitment(vendor: &str, product: &str, version: &str) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}",
        vendor, product, version
    );
    let commitment =
        get_db_commitment(vendor.to_string(), product.to_string(), version.to_string()).commitment;
    debug!("Commitment: {}", commitment);

    return commitment;
}

pub fn get_zkp(_api_key: &str, method: &str, commitment: &str, dependency: &str) {
    match method {
        "Merkle Tree" => {
            info!("Merkle Tree");
            let proof = generate_proof(commitment.to_string(), dependency.to_string());

            print_proof(proof);
        }
        "zkp" => {
            info!("ZKP");
        }
        _ => {
            error!("Unknown method: {}", method);
        }
    }
}

pub fn get_zkp_full(
    _api_key: &str,
    method: &str,
    vendor: &str,
    product: &str,
    version: &str,
    dependency: &str,
) {
    let commitment = get_commitment(vendor, product, version);
    get_zkp(_api_key, method, &commitment, dependency);
}

fn print_proof(proof: MerkleProof<H256, H256>) {
    let config = load_config().unwrap();
    let output_path = config.app.output;

    let path = Path::new(&output_path);
    if let Some(parent) = path.parent() {
        if let Err(e) = create_dir_all(parent) {
            error!("Error creating directory: {}", e);
            return; // Exit early on error
        }
    }

    let mut file = match File::create(&output_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error creating file: {}", e);
            return; // Exit early on error
        }
    };

    if let Err(e) = writeln!(file, "Root: {:?}", proof.root) {
        error!("Error writing to file: {}", e);
        return;
    }
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
    if let Err(e) = writeln!(file, "Leaf: {:?}", proof.leaf) {
        error!("Error writing to file: {}", e);
        return;
    }

    println!("Proof written to: {}", output_path);
}
