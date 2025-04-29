use log::{debug, warn};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use sparse_merkle_tree::{blake2b::Blake2bHasher, CompiledMerkleProof, H256};

fn blake2b_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap(); // 32 bytes output
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize_variable(&mut output).unwrap();
    output
}

fn build_key_and_leaf(name: &str) -> ([u8; 32], [u8; 32]) {
    let key = blake2b_hash(name.as_bytes());
    let mut concat = Vec::from(key);
    concat.extend_from_slice(name.as_bytes());
    let leaf = blake2b_hash(&concat);
    (key, leaf)
}

fn get_kv(leaf: &str) -> (H256, H256) {
    let kv = build_key_and_leaf(&leaf);
    return (H256::from(kv.0), H256::from(kv.1));
}

pub fn verify(commitment: &str, proof_path: &str) -> bool {
    let (proof, leaf, input_key, input_value) = parse_proof_file(proof_path).unwrap();

    // Get Commitment
    let commitment = commitment.strip_prefix("0x").unwrap_or(commitment);
    let commitment = hex::decode(commitment).unwrap();
    let commitment = vec_to_smt_h256(commitment).unwrap();
    debug!("Commitment H256: {:?}", commitment);

    // Check if key and value are correct in case they are present
    let (key, value) = get_kv(&leaf);

    if input_key.is_some() {
        let input_key = input_key.unwrap();
        let input_key = input_key.strip_prefix("0x").unwrap_or(&input_key);

        let input_key = hex::decode(input_key).unwrap();
        let input_key = vec_to_smt_h256(input_key).unwrap();
        debug!("input_key H256: {:?}", input_key);

        if key == input_key {
            debug!("Key is present in Proof File and matches the computed hash.");
        } else {
            warn!("Key Hash is present in Proof File but does not match the computed hash.");
        }
    } else {
        debug!("Key Hash Not Present in Proof File.");
    }

    if input_value.is_some() {
        let input_value = input_value.unwrap();
        let input_value = input_value.strip_prefix("0x").unwrap_or(&input_value);

        let input_value = hex::decode(input_value).unwrap();
        let input_value = vec_to_smt_h256(input_value).unwrap();
        debug!("input_value H256: {:?}", input_value);

        if value == input_value {
            debug!("Value is present in Proof File and matches the computed hash.");
        } else {
            warn!("Value Hash is present in Proof File but does not match the computed hash.");
        }
    } else {
        debug!("Value Hash Not Present in Proof File.");
    }

    // Get Proof
    let proof = proof.strip_prefix("0x").unwrap_or(&proof);
    let proof = hex::decode(proof).unwrap();
    debug!("Proof hex: {:?}", proof);

    let proof = CompiledMerkleProof(proof);
    debug!("Proof casted: {:?}", proof);

    let result = proof
        .verify::<Blake2bHasher>(&commitment, vec![(key, value)])
        .expect("compiled verify");
    debug!("Compiled proof verification result: {:?}", result);

    return result;
}

fn vec_to_smt_h256(vec: Vec<u8>) -> Result<H256, String> {
    if vec.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", vec.len()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&vec);
    Ok(H256::from(arr))
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
