use std::process::Command;
use log::{debug, warn, error};
use sparse_merkle_tree::error;
use crate::hasher::hash_h256_kv;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::str;
// use crate::config::load_config;


pub fn create_commitment(dependencies: Vec<&str>) -> String {
    error!("Creating oZKS commitment...");

    error!("dependencies: {:?}", dependencies);


    // Create key-value pairs for each dependency
    let kv_pairs:Vec<(H256, H256)> = hash_h256_kv(dependencies);
    debug!("Key-Value pairs: {:?}", kv_pairs);

    let mut key_bytes_list_string = String::new();
    let mut value_bytes_list_string = String::new();
    
    for (key, value) in kv_pairs {
        // Convert the keys and values to hex strings
        let key_hex = format!("0x{}", hex::encode(key));
        let value_hex = format!("0x{}", hex::encode(value));

        // COnvert hex strings to bytes
        let key_bytes = hex::decode(key_hex.strip_prefix("0x").unwrap()).unwrap();
        let value_bytes = hex::decode(value_hex.strip_prefix("0x").unwrap()).unwrap();

        // Append to the list strings
        key_bytes_list_string.push_str(&format!("{:?},", key_bytes));
        value_bytes_list_string.push_str(&format!("{:?},", value_bytes));
    }

    // Remove the trailing comma
    if !key_bytes_list_string.is_empty() {
        key_bytes_list_string.pop();
    }
    if !value_bytes_list_string.is_empty() {
        value_bytes_list_string.pop();
    }

    error!("Key list: {}", key_bytes_list_string);
    error!("Value list: {}", value_bytes_list_string);


    warn!("Calling external executable...");

    let output = Command::new("./src/method/ozks/ozks.exe")
        .args(["commitment", &key_bytes_list_string, &value_bytes_list_string])
        .output()
        .expect("Failed to run process");

    warn!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    warn!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    let commitment_byte_string = String::from_utf8_lossy(&output.stdout); 
    // Example: "[5a af 4e c0 2d 51 08 bf a1 cf f2 ef 58 bc 3e 04 da 6f ce f5 fd 31 02 ea 35 be e1 8a 97 23 8f 1a]"

    // Remove brackets and whitespace, then split into hex parts
    let hex_parts: Vec<&str> = commitment_byte_string
        .trim_matches(['[', ']'].as_ref()) // remove brackets
        .split_whitespace() // split on spaces
        .collect();

    // Join all hex parts into a continuous hex string
    // TODO: check if capital letters needed
    let commitment = format!("0x{}", hex_parts.concat());
    error!("oZKS commitment: {}", commitment);

    return commitment;
}

fn generate_proof(root: String, dependency: String) -> String {
    let proof = String::new();
    return proof;
}

pub fn create_proof(commitment: &str, vulnerability: &str) {

}

fn print_proof(proof: String, dependency: String) {

}
