use clap::error;
use log::{debug, info, error};

use binary_merkle_tree::{merkle_root, merkle_proof, verify_proof, MerkleProof};
use serde::de;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;

use hex;

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn verify_merkle(commitment: &str, proof_path: &str) {
    debug!("Commitment: {}, Proof Path: {}", commitment, proof_path);

    let commitment_h256 = str_to_h256(commitment).unwrap();
    error!("Commitment: {:?}", commitment_h256);

    let (root, proof, number_of_leaves, leaf_index, leaf) = parse_proof_file(proof_path).unwrap();
    error!("Root: {}, Proof: {}, Number of Leaves: {}, Leaf Index: {}, Leaf: {}", root, proof, number_of_leaves, leaf_index, leaf);

    // Proof
    let proof_h256 = string_to_h256_vec(&proof).unwrap();
    debug!("Proof: {:?}", proof_h256);

    // Number of leaves
    let number_of_leaves_u32 = number_of_leaves.parse::<u32>().unwrap();
    debug!("Number of leaves: {:?}", number_of_leaves_u32);

    // Leaf index
    let leaf_index_u32 = leaf_index.parse::<u32>().unwrap();
    debug!("Leaf index: {:?}", leaf_index_u32);

    // Leaf
    let leaf_h256 = str_to_h256(&leaf).unwrap();
    debug!("Leaf: {:?}", leaf_h256);


    let is_valid = verify_proof::<BlakeTwo256, Vec<H256>, &_>(
        &commitment_h256,
        proof_h256,
        number_of_leaves_u32,
        leaf_index_u32,
        &leaf_h256
    );

    debug!("Proof is valid: {}", is_valid);

}


pub fn verify_merkle_proof(proof: MerkleProof<H256, H256>) -> bool {
    let is_valid = verify_proof::<BlakeTwo256, Vec<H256>, &_>(
        &proof.root,
        proof.proof,
        proof.number_of_leaves,
        proof.leaf_index,
        &proof.leaf
    );

    debug!("Proof is valid: {}", is_valid);
    return is_valid;
}


fn str_to_h256(input_str: &str) -> Result<H256, hex::FromHexError> {
    let bytes = hex::decode(input_str.trim_start_matches("0x"))?; // Remove "0x" and decode
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength); // H256 must be 32 bytes
    }
    let h256 = H256::from_slice(&bytes); // Create H256 from the byte slice
    Ok(h256)
}

fn parse_proof_file(proof_path: &str) -> Result<(String, String, String, String, String), io::Error> {
    let path = Path::new(proof_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut root = String::new();
    let mut proof = String::new();
    let mut number_of_leaves = String::new();
    let mut leaf_index = String::new();
    let mut leaf = String::new();

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed_line = line.trim();

        if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
            continue;
        }

        if let Some(separator_index) = trimmed_line.find(':') {
            let key = trimmed_line[..separator_index].trim().to_string();
            let value = trimmed_line[separator_index + 1..].trim().to_string();

            match key.as_str() {
                "Root" => root = value,
                "Proof" => proof = value,
                "Number of Leaves" => number_of_leaves = value,
                "Leaf Index" => leaf_index = value,
                "Leaf" => leaf = value,
                
                _ => eprintln!("Warning: Unknown key: {}", key), // Handle unknown keys
            }
        } else {
            eprintln!("Warning: Invalid line format: {}", trimmed_line);
        }
    }

    Ok((root, proof, number_of_leaves, leaf_index, leaf))
}

fn string_to_h256_vec(s: &str) -> Result<Vec<H256>, String> {
    let hashes_str = s.trim_matches(|p| p == '[' || p == ']');
    let hash_strings = hashes_str.split(",").collect::<Vec<&str>>();

    let mut h256_vec = Vec::new();

    for hash_str in hash_strings {
        let cleaned_hash_str = hash_str.trim(); // Just trim whitespace
        match str_to_h256(cleaned_hash_str) {
            Ok(h256) => h256_vec.push(h256),
            Err(err) => return Err(format!("Error parsing hash: {}", err)),
        }
    }

    Ok(h256_vec)
}
