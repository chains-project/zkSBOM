use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_patricia_trie::{
    create_commitment as create_merkle_patricia_trie_commitment,
    create_proof as create_merkle_patricia_trie_proof,
};
use crate::method::merkle_tree::{
    create_commitment as create_merkle_commitment, create_proof as create_merkle_proof,
};
use crate::method::sparse_merkle_tree::{
    create_commitment as create_sparse_merkle_commitment,
    create_proof as create_sparse_merkle_proof,
};
use log::{debug, error};
use std::str;

pub fn create_commitments(dependencies: Vec<&str>) -> Vec<String> {
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

    // Merkle Patricia Trie
    debug!("Create Merkle Patricia Trie commitment");
    let merkle_patricia_trie_commitment =
        create_merkle_patricia_trie_commitment(dependencies.clone());
    debug!(
        "Merkle Patricia Trie Commitment: {:?}",
        merkle_patricia_trie_commitment
    );

    return vec![
        merkle_tree_commitment,
        sparse_merkle_tree_commitment,
        merkle_patricia_trie_commitment,
    ];
}

pub fn get_commitment(vendor: &str, product: &str, version: &str, method: &str) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}, method: {}",
        vendor, product, version, method
    );

    let commitment;
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
        "merkle-patricia-trie" => {
            commitment =
                get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                    .commitment_merkle_patricia_trie;
            debug!("Merkle Patricia Trie Commitment: {}", commitment);
        }
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
        "merkle-patricia-trie" => {
            create_merkle_patricia_trie_proof(commitment, vulnerability);
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
