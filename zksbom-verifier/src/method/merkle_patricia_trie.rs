use log::{debug, error, warn};
use reference_trie::NoExtensionLayout;
use sp_core::{Hasher, H256};
use sp_runtime::traits::BlakeTwo256;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use trie_db::{proof::verify_proof, DBValue};

pub struct VerificationResult {
    pub is_valid: bool,
    pub is_non_inclusion: bool,
    pub details: Vec<ProofVerificationDetail>,
}

pub struct ProofVerificationDetail {
    pub leaf: String,
    pub is_proof_valid: bool,
}

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

    // Prepare Commitment
    let commitment = commitment.strip_prefix("0x").unwrap_or(commitment);
    let commitment = match hex::decode(commitment) {
        Ok(bytes) => match <[u8; 32]>::try_from(bytes) {
            Ok(arr) => arr,
            Err(e) => {
                error!("Failed to convert commitment to [u8; 32]: {:?}", e);
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

    let mut all_valid = true;
    let mut details = Vec::new();
    let mut is_non_inclusion = false;

    for (idx, (proof_hex, leaf, input_key, input_value)) in proofs.into_iter().enumerate() {
        debug!(
            "Verifying proof {} of {}: leaf '{}'",
            idx + 1,
            num_proofs,
            leaf
        );

        // Check if key and value are correct in case they are present
        let kv_calc = hash_h256_kv(vec![&leaf]);
        let key_calc = kv_calc.get(0).unwrap().0.as_bytes();
        let value_calc = kv_calc.get(0).unwrap().1.as_bytes();

        let mut key_binding_valid = true;

        if let Some(input_key) = &input_key {
            let input_key_str = input_key.strip_prefix("0x").unwrap_or(&input_key);
            match hex::decode(input_key_str) {
                Ok(decoded) => {
                    if key_calc == decoded.as_slice() {
                        debug!("Key is present in Proof File and matches the computed hash.");
                    } else {
                        warn!("Key Hash is present in Proof File but does not match the computed hash.");
                        key_binding_valid = false;
                        all_valid = false;
                    }
                }
                Err(e) => {
                    error!("Failed to decode input key hex: {}", e);
                    key_binding_valid = false;
                    all_valid = false;
                }
            }
        } else {
            debug!("Key Hash Not Present in Proof File.");
        }

        let mut value_binding_valid = true;

        if let Some(input_value) = &input_value {
            let input_value_str = input_value.strip_prefix("0x").unwrap_or(&input_value);
            match hex::decode(input_value_str) {
                Ok(decoded) => {
                    if value_calc == decoded.as_slice() {
                        debug!("Value is present in Proof File and matches the computed hash.");
                    } else {
                        warn!("Value Hash is present in Proof File but does not match the computed hash.");
                        value_binding_valid = false;
                        all_valid = false;
                    }
                }
                Err(e) => {
                    error!("Failed to decode input value hex: {}", e);
                    value_binding_valid = false;
                    all_valid = false;
                }
            }
        } else {
            debug!("Value Hash Not Present in Proof File.");
        }

        // Get Proof
        let proof = proof_hex.split(";").collect::<Vec<&str>>();
        let proof = proof
            .iter()
            .map(|part| part.strip_prefix("0x").unwrap_or(part))
            .collect::<Vec<&str>>();
        let proof = match proof
            .iter()
            .map(|part| hex::decode(part))
            .collect::<Result<Vec<Vec<u8>>, _>>()
        {
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

        // Prepare Value
        let input_value_decoded = match input_value {
            Some(val) => {
                let val_str = val.strip_prefix("0x").unwrap_or(&val);
                match hex::decode(val_str) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode input value: {}", e);
                        all_valid = false;
                        details.push(ProofVerificationDetail {
                            leaf: leaf.clone(),
                            is_proof_valid: false,
                        });
                        continue;
                    }
                }
            }
            None => {
                error!("Input value is required for verification");
                all_valid = false;
                details.push(ProofVerificationDetail {
                    leaf: leaf.clone(),
                    is_proof_valid: false,
                });
                continue;
            }
        };

        // Prepare Key
        let input_key_decoded = match input_key {
            Some(key) => {
                let key_str = key.strip_prefix("0x").unwrap_or(&key);
                match hex::decode(key_str) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        error!("Failed to decode input key: {}", e);
                        all_valid = false;
                        details.push(ProofVerificationDetail {
                            leaf: leaf.clone(),
                            is_proof_valid: false,
                        });
                        continue;
                    }
                }
            }
            None => {
                error!("Input key is required for verification");
                all_valid = false;
                details.push(ProofVerificationDetail {
                    leaf: leaf.clone(),
                    is_proof_valid: false,
                });
                continue;
            }
        };

        // Prepare Items with Key and Value
        let items_new: Vec<(Vec<u8>, Option<DBValue>)> =
            vec![(input_key_decoded, Some(input_value_decoded))];

        // Verify Proof
        let res = verify_proof::<NoExtensionLayout, _, _, _>(&commitment, &proof, items_new.iter());

        let proof_valid = match res {
            Ok(()) => {
                debug!("Proof is valid!");
                debug!("Leaf in trie");
                true
            }
            Err(e) => {
                debug!("Proof verification error: {:?}", e);
                let err_str = format!("{:?}", e);
                is_non_inclusion = true;
                err_str.contains("ValueMismatch")
            }
        };

        if !proof_valid || !key_binding_valid || !value_binding_valid {
            all_valid = false;
        }

        details.push(ProofVerificationDetail {
            leaf: leaf.clone(),
            is_proof_valid: proof_valid && key_binding_valid && value_binding_valid,
        });
    }

    VerificationResult {
        is_valid: all_valid,
        is_non_inclusion: is_non_inclusion,
        details,
    }
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
