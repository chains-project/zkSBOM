use log::{debug, error, warn};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use sparse_merkle_tree::{blake2b::Blake2bHasher, CompiledMerkleProof, H256};

pub struct VerificationResult {
    pub is_valid: bool,
    pub is_non_inclusion: bool,
    pub details: Vec<ProofVerificationDetail>,
}

pub struct ProofVerificationDetail {
    pub leaf: String,
    pub is_proof_valid: bool,
}

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

pub fn verify(commitment: &str, proof_path: &str) -> VerificationResult {
    debug!("Commitment: {}, Proof Path: {}", commitment, proof_path);

    let proofs = match parse_proof_file(proof_path) {
        Ok(proofs) => proofs,
        Err(e) => {
            error!("Failed to parse proof file: {}", e);
            return VerificationResult {
                is_valid: false,
                is_non_inclusion: false,
                details: vec![],
            };
        }
    };

    let num_proofs = proofs.len();
    debug!("Found {} proof(s) in file", num_proofs);

    // Get Commitment
    let commitment = commitment.strip_prefix("0x").unwrap_or(commitment);
    let commitment = match hex::decode(commitment) {
        Ok(bytes) => match vec_to_smt_h256(bytes) {
            Ok(h256) => h256,
            Err(e) => {
                error!("Failed to convert commitment to H256: {}", e);
                return VerificationResult {
                    is_valid: false,
                    is_non_inclusion: false,
                    details: vec![],
                };
            }
        },
        Err(e) => {
            error!("Failed to decode commitment hex: {}", e);
            return VerificationResult {
                is_valid: false,
                is_non_inclusion: false,
                details: vec![],
            };
        }
    };
    debug!("Commitment H256: {:?}", commitment);

    let mut all_valid = true;
    let mut details = Vec::new();
    let mut is_none_inclusion = false;

    for (idx, (proof_hex, leaf, input_key, input_value)) in proofs.into_iter().enumerate() {
        debug!(
            "Verifying proof {} of {}: leaf '{}'",
            idx + 1,
            num_proofs,
            leaf
        );

        // Check if key and value are correct in case they are present
        let (key, value) = get_kv(&leaf);

        if let Some(input_key) = input_key {
            let input_key = input_key.strip_prefix("0x").unwrap_or(&input_key);

            match hex::decode(input_key) {
                Ok(bytes) => match vec_to_smt_h256(bytes) {
                    Ok(input_key_h256) => {
                        debug!("input_key H256: {:?}", input_key_h256);

                        if key == input_key_h256 {
                            debug!("Key is present in Proof File and matches the computed hash.");
                        } else {
                            warn!("Key Hash is present in Proof File but does not match the computed hash.");
                            all_valid = false;
                        }
                    }
                    Err(e) => {
                        error!("Failed to convert input key to H256: {}", e);
                        all_valid = false;
                    }
                },
                Err(e) => {
                    error!("Failed to decode input key hex: {}", e);
                    all_valid = false;
                }
            }
        } else {
            debug!("Key Hash Not Present in Proof File.");
        }

        if let Some(input_value) = input_value {
            let input_value = input_value.strip_prefix("0x").unwrap_or(&input_value);

            match hex::decode(input_value) {
                Ok(bytes) => match vec_to_smt_h256(bytes) {
                    Ok(input_value_h256) => {
                        debug!("input_value H256: {:?}", input_value_h256);

                        if value == input_value_h256 {
                            debug!("Value is present in Proof File and matches the computed hash.");
                        } else {
                            warn!("Value Hash is present in Proof File but does not match the computed hash.");
                            all_valid = false;
                        }
                    }
                    Err(e) => {
                        error!("Failed to convert input value to H256: {}", e);
                        all_valid = false;
                    }
                },
                Err(e) => {
                    error!("Failed to decode input value hex: {}", e);
                    all_valid = false;
                }
            }
        } else {
            debug!("Value Hash Not Present in Proof File.");
        }

        // Get Proof
        let proof = proof_hex.strip_prefix("0x").unwrap_or(&proof_hex);
        let proof = match hex::decode(proof) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to decode proof hex: {}", e);
                all_valid = false;
                details.push(ProofVerificationDetail {
                    leaf: leaf.clone(),
                    is_proof_valid: false,
                });
                continue;
            }
        };
        debug!("Proof hex length: {}", proof.len());

        let proof = CompiledMerkleProof(proof);
        debug!("Proof casted: {:?}", proof);

        let mut result = match proof.verify::<Blake2bHasher>(&commitment, vec![(key, value)]) {
            Ok(r) => r,
            Err(e) => {
                error!("Proof verification failed: {:?}", e);
                all_valid = false;
                false
            }
        };
        debug!("Compiled proof verification result: {:?}", result);

        if !result {
            // Test for non-inclusion
            let nip_result =
                match proof.verify::<Blake2bHasher>(&commitment, vec![(key, H256::zero())]) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Proof verification failed: {:?}", e);
                        all_valid = false;
                        false
                    }
                };

            if !nip_result {
                all_valid = false;
            } else {
                is_none_inclusion = true;
                result = true;
            }
        }

        details.push(ProofVerificationDetail {
            leaf: leaf.clone(),
            is_proof_valid: result,
        });
    }

    VerificationResult {
        is_valid: all_valid,
        is_non_inclusion: is_none_inclusion,
        details,
    }
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
) -> Result<Vec<(String, String, Option<String>, Option<String>)>, io::Error> {
    let path = Path::new(proof_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut proofs: Vec<(String, String, Option<String>, Option<String>)> = Vec::new();
    let mut current_proof = String::new();
    let mut current_leaf = String::new();
    let mut current_key = String::new();
    let mut current_value = String::new();

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed_line = line.trim();

        // Check for separator between proofs
        if trimmed_line == "---" {
            if !current_proof.is_empty() && !current_leaf.is_empty() {
                let key = if current_key.is_empty() {
                    None
                } else {
                    Some(current_key.clone())
                };
                let value = if current_value.is_empty() {
                    None
                } else {
                    Some(current_value.clone())
                };
                proofs.push((current_proof.clone(), current_leaf.clone(), key, value));
                current_proof.clear();
                current_leaf.clear();
                current_key.clear();
                current_value.clear();
            }
            continue;
        }

        if trimmed_line.is_empty() || trimmed_line.starts_with("#") {
            continue;
        }

        if let Some(separator_index) = trimmed_line.find(':') {
            let key = trimmed_line[..separator_index].trim().to_string();
            let value = trimmed_line[separator_index + 1..].trim().to_string();

            match key.as_str() {
                "Proof" => current_proof = value,
                "Leaf" => current_leaf = value,
                "Key" => current_key = value,
                "Value" => current_value = value,
                _ => debug!("Ignoring unknown key: {}", key),
            }
        } else {
            debug!("Ignoring line without key-value format: {}", trimmed_line);
        }
    }

    // Don't forget to add the last proof if it exists
    if !current_proof.is_empty() && !current_leaf.is_empty() {
        let key = if current_key.is_empty() {
            None
        } else {
            Some(current_key)
        };
        let value = if current_value.is_empty() {
            None
        } else {
            Some(current_value)
        };
        proofs.push((current_proof, current_leaf, key, value));
    }

    Ok(proofs)
}
