use std::process::Command;
use log::{debug, warn, error};
use sparse_merkle_tree::error;
use crate::hasher::hash_h256_kv;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::str;
use crate::config::load_config;
use crate::map_dependencies_vulnerabilities::get_mapping_for_dependencies;
use crate::database::db_dependency::get_dependencies;
// use crate::database::db_dependency::get_dependencies;
use crate::database::db_ozks::{insert_ozks, OzksDbEntry, get_ozks};

use reqwest::blocking::Client; // Import the blocking client
use serde::{Serialize, Deserialize};
use std::collections::HashMap; // Still useful if you need dynamic query params, though direct tuple is used here

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;


// For the /add_zks endpoint request body
#[derive(Serialize)]
struct AddZksRequest {
    keys: String,   // Hex string
    values: String, // Hex string
}

// For the /add_zks endpoint response
#[derive(Deserialize)]
struct AddZksResponse {
    status: String,
    commitment: String,
}




fn hex_to_spaced_bytes(hex: &str) -> Result<String, String> {
    // Remove optional "0x" prefix
    let clean_hex = hex.trim_start_matches("0x");

    // Check that length is even
    if clean_hex.len() % 2 != 0 {
        return Err("Hex string length must be even".to_string());
    }

    // Convert to spaced byte format
    let bytes: Result<Vec<String>, _> = (0..clean_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean_hex[i..i + 2], 16)
             .map(|b| format!("{:02x}", b)))
        .collect();

    match bytes {
        Ok(vec) => Ok(format!("[{}]", vec.join(", "))),
        Err(_) => Err("Invalid hex input".to_string()),
    }
}

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    error!("Creating oZKS commitment...");

    error!("!!!Dependencies: {:?}", dependencies);


    // Create key-value pairs for each dependency
    let kv_pairs:Vec<(H256, H256)> = hash_h256_kv(dependencies);
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

    error!("Key list: {}", key_bytes_list_string);
    error!("Value list: {}", value_bytes_list_string);



    warn!("Calling http endpoint for add_zks");
    let client = Client::new();
    let base_url = "http://localhost:8080"; 
    
    let keys = key_bytes_list_string.clone();
    let values = value_bytes_list_string.clone();

    let add_zks_payload = AddZksRequest {
        keys,
        values,
    };

    let add_zks_res = client
        .post(&format!("{}/add_zks", base_url))
        .json(&add_zks_payload) // Still works with blocking client
        .send()
        .unwrap(); // No .await


    let add_zks_status = add_zks_res.status();
    let add_zks_body: AddZksResponse = add_zks_res.json().unwrap();

    error!("Response Status: {}", add_zks_status);
    error!("Response Body: Status = {}, Commitment = {}", add_zks_body.status, add_zks_body.commitment);




    // warn!("Calling external executable...");

    // let output = Command::new("./src/method/ozks/ozks.exe")
    //     .args(["commitment", &key_bytes_list_string, &value_bytes_list_string])
    //     .output()
    //     .expect("Failed to run process");

    // warn!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    // warn!("stderr: {}", String::from_utf8_lossy(&output.stderr));


    // // SPlit stdout by ';'
    // let binding = String::from_utf8_lossy(&output.stdout);
    // let parts: Vec<&str> = binding.split(';').collect();
    // error!("Parts: {:?}", parts);

    // error!("Commitment bytes: {}", parts[0]);
    // let commitment_byte_string = parts[0];

    // // Remove brackets and whitespace, then split into hex parts
    // let hex_parts: Vec<&str> = commitment_byte_string
    //     .trim_start_matches("\r\n")
    //     .trim_matches(['[', ']'].as_ref()) // remove brackets
    //     .split_whitespace() // split on spaces
    //     .map(|s| s.trim_matches(']')) // remove any trailing ']'
    //     .collect();
    // let commitment = format!("0x{}", hex_parts.concat());
    // error!("oZKS commitment: {}", commitment);


    // error!("zks_bytes: {}", parts[1]);
    // let zks_byte_string = parts[1];
    // // Remove brackets and whitespace, then split into hex parts
    // let hex_parts: Vec<&str> = zks_byte_string
    //     .trim_start_matches("\r\n")
    //     .trim_matches(['[', ']'].as_ref()) // remove brackets
    //     .split_whitespace() // split on spaces
    //     .map(|s| s.trim_matches(']')) // remove any trailing ']'
    //     .collect();
    // let zks = format!("0x{}", hex_parts.concat());
    // error!("-----------------zks: {}", zks);

    // // error!("zks hex: {}", parts[1]);
    // // let zks_hex = format!("0x{}", hex::encode(parts[1]));
    // // error!("!!!!!!!!zks hex: {}", zks_hex);
    // // let zks = zks_hex;

    
    // error!("config bytes: {}", parts[2]);
    // let config_byte_string = parts[2];
    //     // Remove brackets and whitespace, then split into hex parts
    // let hex_parts: Vec<&str> = config_byte_string
    //     .trim_start_matches("\r\n")
    //     .trim_matches(['[', ']'].as_ref()) // remove brackets
    //     .split_whitespace() // split on spaces
    //     .map(|s| s.trim_matches(']')) // remove any trailing ']'
    //     .collect();
    // let config = format!("0x{}", hex_parts.concat());
    // error!("config: {}", config);





    // let ozks_entry = OzksDbEntry {
    //     commitment: commitment.clone(),
    //     zks: zks.clone(),
    //     config: config.clone(),
    // };
    // insert_ozks(ozks_entry);





    let commitment = add_zks_body.commitment; // Replace with actual commitment generation logic
    return commitment;
}

fn generate_proof(commitment: String, dependencies: Vec<&str>, dependency: String) -> String {
    error!("Generating proof for dependency: {}", dependency);
    error!("Commitment: {}", commitment);
    error!("!!!!!Dependencies: {:?}", dependencies);
    


    // Prepare dependecy to proof
    let dep_kv_pair:Vec<(H256, H256)> = hash_h256_kv(vec![&dependency]);
    error!("Dependency Key-Value pair: {:?}", dep_kv_pair);
    let key_hex = format!("0x{}", hex::encode(dep_kv_pair[0].0));
    let key_bytes = hex::decode(key_hex.strip_prefix("0x").unwrap()).unwrap();
    let hex_bytes_string = format!("{:?}", key_bytes);
    // error!("Dependency Key bytes string: {}", hex_bytes_string);

    let dependency_key = hex_bytes_string.clone();
    warn!("Dependency Key: {}", dependency_key);


    let client = Client::new(); // Create a blocking client
    let base_url = "http://localhost:8080";

    let get_query_res = client
        .get(&format!("{}/get_query_result", base_url))
        .query(&[("commitment", &commitment), ("dependency_key", &dependency_key)])
        .send()
        .unwrap(); // No .await

    let get_query_status = get_query_res.status();
    let get_query_body = get_query_res.text().unwrap(); // No .await


    error!("Response Status: {}", get_query_status);
    error!("Response Body: {}", get_query_body);


    if get_query_status.is_success() {
        warn!("Successfully got query result: {}", get_query_body);
    } else {
        error!("Failed to get query result: {}", get_query_body);
    }


    // warn!("Calling http server...");

    // let output = Command::new("./src/method/ozks/ozks.exe")
    //     .args(["proof",
    //     &commitment_bytes_string,
    //     &zks_hex_bytes_string,
    //     &config_hex_bytes_string,
    //     // &key_bytes_list_string,
    //     // &value_bytes_list_string,
    //     &hex_bytes_string])
    //     .output()
    //     .expect("Failed to run process");

    // warn!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    // warn!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    // let commitment_byte_string = String::from_utf8_lossy(&output.stdout); 
    
    


    
    let proof = get_query_body;
    return proof;
}





pub fn create_proof(commitment: &str, vulnerability: &str) {
    let dependency_entry = get_dependencies(commitment.to_string(), "ozks");
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone());


    // error!("Dependencies: {:?}", dependencies);

    for dep in dependencies.clone() {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);
        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&vulnerability.to_string()) {
                error!("Dependency: {} is vulnerable to: {}", dep, vulnerability);
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
