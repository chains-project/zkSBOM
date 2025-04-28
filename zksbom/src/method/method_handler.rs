use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_tree::{
    create_commitment as create_merkle_commitment, create_proof as create_merkle_proof,
};
use crate::method::sparse_merkle_tree::{
    create_commitment as create_sparse_merkle_commitment,
    create_proof as create_sparse_merkle_proof,
};
use log::{debug, error};
use std::str;

pub fn create_commitments(dependencies: Vec<&str>) -> (String, String) {
    // Merkle Tree
    debug!("Create Merkle Tree commitment");
    let merkle_tree_commitment = create_merkle_commitment(dependencies.clone());
    debug!("Merkle Tree Commitment: {}", merkle_tree_commitment);

    // Sparse Merkle Tree
    debug!("Create Sparse Merkle Tree commitment");
    let sparse_merkle_tree_commitment = create_sparse_merkle_commitment(dependencies.clone());
    debug!(
        "Sparse Merkle Tree Commitment: {:?}",
        sparse_merkle_tree_commitment
    );

    return (merkle_tree_commitment, sparse_merkle_tree_commitment);
}

pub fn get_commitment(vendor: &str, product: &str, version: &str, method: &str) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}, method: {}",
        vendor, product, version, method
    );

    let mut commitment = String::new();
    match method {
        "merkle-tree" => {
            commitment =
                get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                    .commitment_merkle_tree;
            debug!("Merkle Tree Commitment: {}", commitment);
        }
        "sparse-merkle-tree" => {
            commitment =
                get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                    .commitment_sparse_merkle_tree;
            debug!("Merkle Tree Commitment: {}", commitment);
        }
        "zkp" => {}
        _ => {
            panic!("Unknown method: {}", method);
        }
    }

    return commitment;
}

pub fn get_zkp(_api_key: &str, method: &str, commitment: &str, vulnerability: &str) {
    match method {
        "merkle-tree" => {
            create_merkle_proof(commitment, vulnerability);
        }
        "sparse-merkle-tree" => {
            create_sparse_merkle_proof(commitment, vulnerability);
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
    let commitment = get_commitment(vendor, product, version, method);
    get_zkp(_api_key, method, &commitment, vulnerability);
}
