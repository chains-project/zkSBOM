use log::{debug, error, warn};
use reference_trie::NoExtensionLayout;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use trie_db::{proof::verify_proof, DBValue};

pub fn hash_h256_kv(dependencies_clear_text: Vec<&str>) -> Vec<(H256, H256)> {
    let mut hash_kv: Vec<(H256, H256)> = Vec::new();
    for dependency_clear_text in dependencies_clear_text {
        let value = H256::from_slice(&BlakeTwo256::hash(dependency_clear_text.as_bytes()).0);
        // Key is hash(dependency_clear_text + value)
        let mut key_bytes = dependency_clear_text.as_bytes().to_vec(); // Convert to a mutable Vec<u8>
        key_bytes.extend_from_slice(value.as_bytes()); // Use extend_from_slice on the Vec
        let key = H256::from_slice(&BlakeTwo256::hash(&key_bytes).0); // Hash the combined Vec
        hash_kv.push((key, value));
    }
    return hash_kv;
}

pub fn verify(commitment: &str, proof_path: &str) -> bool {
    let (proof, leaf, input_key, input_value) = parse_proof_file(proof_path).unwrap();

    // Prepare Commitment
    let commitment = commitment.strip_prefix("0x").unwrap_or(commitment);
    let commitment = hex::decode(commitment).unwrap();
    let commitment: [u8; 32] = commitment.try_into().unwrap();

    // Check if key and value are correct in case they are present
    let kv_calc = hash_h256_kv(vec![&leaf]);
    let key_calc = kv_calc.get(0).unwrap().0.as_bytes();
    let value_calc = kv_calc.get(0).unwrap().1.as_bytes();

    if input_key.is_some() {
        let input_key = input_key.clone().unwrap();
        let input_key = input_key.strip_prefix("0x").unwrap_or(&input_key);
        let input_key = hex::decode(input_key).unwrap();

        if key_calc == input_key {
            debug!("Key is present in Proof File and matches the computed hash.");
        } else {
            warn!("Key Hash is present in Proof File but does not match the computed hash.");
        }
    } else {
        debug!("Key Hash Not Present in Proof File.");
    }

    if input_value.is_some() {
        let input_value = input_value.clone().unwrap();
        let input_value = input_value.strip_prefix("0x").unwrap_or(&input_value);
        let input_value = hex::decode(input_value).unwrap();

        if value_calc == input_value {
            debug!("Value is present in Proof File and matches the computed hash.");
        } else {
            warn!("Value Hash is present in Proof File but does not match the computed hash.");
        }
    } else {
        debug!("Value Hash Not Present in Proof File.");
    }

    // Get Proof
    let proof = proof.split(";").collect::<Vec<&str>>();
    let proof = proof
        .iter()
        .map(|part| part.strip_prefix("0x").unwrap_or(part))
        .collect::<Vec<&str>>();
    let proof = proof
        .iter()
        .map(|part| hex::decode(part).unwrap())
        .collect::<Vec<Vec<u8>>>();

    // Prepare Value
    let input_value_hex = input_value.unwrap();
    let input_value_hex = input_value_hex
        .strip_prefix("0x")
        .unwrap_or(&input_value_hex);
    let input_value_decoded = hex::decode(input_value_hex).unwrap();
    let input_value_decoded = input_value_decoded.to_vec();

    // Prepare Key
    let input_key_hex = input_key.unwrap();
    let input_key_hex = input_key_hex.strip_prefix("0x").unwrap_or(&input_key_hex);
    let input_key_decoded = hex::decode(input_key_hex).unwrap();
    let input_key_decoded = input_key_decoded.to_vec();

    // Prepare Items with Key and Value
    let items_new: Vec<(Vec<u8>, Option<DBValue>)> =
        vec![(input_key_decoded, Some(input_value_decoded))];

    // Verify Proof
    let res = verify_proof::<NoExtensionLayout, _, _, _>(&commitment, &proof, items_new.iter());

    match res {
        Ok(_) => {
            debug!("Leaf in trie");
            return true;
        }
        Err(_) => {
            error!("Leaf not in trie");
            return false;
        }
    }
}

fn parse_proof_file(
    proof_path: &str,
) -> Result<(String, String, Option<String>, Option<String>), io::Error> {
    let path = Path::new(proof_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut proof = String::new();
    let mut leaf = String::new();
    let mut key = String::new();
    let mut value = String::new();

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed_line = line.trim();

        if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
            continue;
        }

        if let Some(separator_index) = trimmed_line.find(':') {
            let i_key = trimmed_line[..separator_index].trim().to_string();
            let i_value = trimmed_line[separator_index + 1..].trim().to_string();

            match i_key.as_str() {
                "Proof" => proof = i_value,
                "Leaf" => leaf = i_value,
                "Key" => key = i_value,
                "Value" => value = i_value,
                _ => eprintln!("Warning: Unknown key: {}", i_key), // Handle unknown keys
            }
        } else {
            eprintln!("Warning: Invalid line format: {}", trimmed_line);
        }
    }

    let key = if key.is_empty() { None } else { Some(key) };
    let value = if value.is_empty() { None } else { Some(value) };

    Ok((proof, leaf, key, value))
}
