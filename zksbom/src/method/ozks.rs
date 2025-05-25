use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256_kv;
use crate::map_dependencies_vulnerabilities::get_mapping_for_dependencies;
use log::{debug, error};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str;

#[derive(Serialize)]
struct AddZksRequest {
    keys: String,
    values: String,
}

#[derive(Deserialize)]
struct AddZksResponse {
    status: String,
    commitment: String,
}

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    debug!("Creating oZKS commitment...");
    debug!("Dependencies: {:?}", dependencies);

    // Create key-value pairs for each dependency
    let kv_pairs: Vec<(H256, H256)> = hash_h256_kv(dependencies);
    debug!("Key-Value pairs: {:?}", kv_pairs);

    let mut key_bytes_list_string = String::new();
    let mut value_bytes_list_string = String::new();

    for (key, value) in kv_pairs {
        // Convert the keys and values to hex strings
        let key_hex = format!("0x{}", hex::encode(key));
        let value_hex = format!("0x{}", hex::encode(value));

        // Convert hex strings to bytes
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

    debug!("Key list: {}", key_bytes_list_string);
    debug!("Value list: {}", value_bytes_list_string);

    debug!("Calling http endpoint for add_zks");
    let client = Client::new();
    let base_url = "http://localhost:8080";

    let keys = key_bytes_list_string.clone();
    let values = value_bytes_list_string.clone();

    let add_zks_payload = AddZksRequest { keys, values };

    let add_zks_res = client
        .post(&format!("{}/add_zks", base_url))
        .json(&add_zks_payload) // Still works with blocking client
        .send()
        .unwrap(); // No .await

    let add_zks_status = add_zks_res.status();
    let add_zks_body: AddZksResponse = add_zks_res.json().unwrap();

    debug!("Response Status: {}", add_zks_status);
    debug!(
        "Response Body: Status = {}, Commitment = {}",
        add_zks_body.status, add_zks_body.commitment
    );

    let commitment = add_zks_body.commitment; // Replace with actual commitment generation logic
    return commitment;
}

fn generate_proof(commitment: String, _dependencies: Vec<&str>, dependency: String) -> String {
    debug!(
        "Generating proof for dependency: {}; with commitment: {}",
        dependency, commitment
    );

    // Prepare dependecy to proof
    let dep_kv_pair: Vec<(H256, H256)> = hash_h256_kv(vec![&dependency]);
    debug!("Dependency Key-Value pair: {:?}", dep_kv_pair);
    let key_hex = format!("0x{}", hex::encode(dep_kv_pair[0].0));
    let key_bytes = hex::decode(key_hex.strip_prefix("0x").unwrap()).unwrap();
    let hex_bytes_string = format!("{:?}", key_bytes);

    let dependency_key = hex_bytes_string.clone();
    debug!("Dependency Key: {}", dependency_key);

    let client = Client::new();
    let base_url = "http://localhost:8080";

    let get_query_res = client
        .get(&format!("{}/get_query_result", base_url))
        .query(&[
            ("commitment", &commitment),
            ("dependency_key", &dependency_key),
        ])
        .send()
        .unwrap(); // No .await

    let get_query_status = get_query_res.status();
    let get_query_body = get_query_res.text().unwrap(); // No .await

    debug!("Response Status: {}", get_query_status);
    debug!("Response Body: {}", get_query_body);

    if get_query_status.is_success() {
        debug!("Successfully got query result: {}", get_query_body);
    } else {
        error!("Failed to get query result: {}", get_query_body);
    }

    let proof = get_query_body;
    return proof;
}

pub fn create_proof(commitment: &str, vulnerability: &str) {
    let dependency_entry = get_dependencies(commitment.to_string(), "ozks");
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone());

    for dep in dependencies.clone() {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);
        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&vulnerability.to_string()) {
                debug!("Dependency: {} is vulnerable to: {}", dep, vulnerability);
                let proof = generate_proof(commitment.to_string(), dependencies, dep.to_string());
                print_proof(proof, dep.to_string());

                break; // Break the loop after finding the first match
            }
        }
    }
}

fn print_proof(proof: String, dependency: String) {
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

    if let Err(e) = writeln!(file, "Proof: {}", proof) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "Dependency: {}", dependency) {
        error!("Error writing to file: {}", e);
        return;
    }
}
