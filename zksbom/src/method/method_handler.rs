use log::{debug, info, warn, error};
use crate::method::merkle_tree::{create_commitment as create_merkle_commitment, MerkleRootLeaves};

use crate::database::db_commitment::{CommitmentDbEntry, init_db_commitment, insert_commitment, get_commitment as get_db_commitment, delete_db_commitment};

pub fn create_commitment(vulnerabilities: Vec<&str>) -> (String, Vec<String>) {
    // TODO: Implement handling for different methods
    let merkle_root_leaves = create_merkle_commitment(vulnerabilities);
    let commitment = merkle_root_leaves.root;
    let vulnerabilities = merkle_root_leaves.leaves;
    
    return (commitment, vulnerabilities);
}

pub fn get_commitment(vendor: &str, product: &str, version: &str) -> String {
    debug!("Getting commitment for vendor: {}, product: {}, version: {}", vendor, product, version);
    let commitment = get_db_commitment(vendor.to_string(), product.to_string(), version.to_string()).commitment;
    debug!("Commitment: {}", commitment);

    return commitment;
}

pub fn get_zkp(api_key: &str, method: &str, commitment: &str, vulnerability: &str) {
    panic!("Implement get_zkp");
    
    // if commitment.is_empty() {
    //     println!("Commitment is empty");
    //     return;
    // }
    // match mehtod{
    //     "merkle" => {
    //         println!("Merkle");
    //     }
    //     "zkp" => {
    //         println!("ZKP");
    //     }
    //     _ => {
    //         println!("Unknown method: {}", mehtod);
    //     }
    // }
}

