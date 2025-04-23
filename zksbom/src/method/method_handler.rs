use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_tree::{
    create_commitment as create_merkle_commitment, create_merkle_proof,
};
use log::{debug, error};
use std::str;

pub fn create_commitment(dependencies: Vec<&str>) -> (String, Vec<String>) {
    // TODO: Implement handling for different methods
    // Merkle Tree
    debug!("Create Merkle Tree commitment");
    let merkle_root_leaves = create_merkle_commitment(dependencies);
    let merkle_tree_commitment = merkle_root_leaves.root;
    let merkle_tree_dependencies = merkle_root_leaves.leaves;

    return (merkle_tree_commitment, merkle_tree_dependencies);
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

pub fn get_zkp(_api_key: &str, method: &str, commitment: &str, vulnerability: &str) {
    match method {
        "merkle-tree" => {
            create_merkle_proof(commitment, vulnerability);
        }
        "sparse-merkle-tree" => {
            error!("sparse-merkle-tree not implemented yet");
        }
        "zkp" => {
            error!("zkp not implemented yet");
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
    vulnerability: &str,
) {
    let commitment = get_commitment(vendor, product, version);
    get_zkp(_api_key, method, &commitment, vulnerability);
}
