use crate::hasher::hash_h256_kv;
use hex;
use log::{debug, error, warn};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub struct VerificationResult {
    pub is_valid: bool,
    pub details: Vec<ProofVerificationDetail>,
}

pub struct ProofVerificationDetail {
    pub dependency: String,
    pub is_member: bool,
    pub is_proof_valid: bool,
}

pub fn verify(commitment: &str, proof_path: &str) -> VerificationResult {
    debug!("Commitment: {}, Proof Path: {}", commitment, proof_path);

    let proofs = match parse_proof_file(proof_path) {
        Ok(proofs) => proofs,
        Err(e) => {
            error!("Failed to parse proof file: {}", e);
            return VerificationResult {
                is_valid: false,
                details: vec![],
            };
        }
    };

    debug!("Found {} proof(s) in file", proofs.len());

    // Decode commitment hex string to bytes (strip optional 0x prefix)
    let commitment_bytes = match hex::decode(commitment.strip_prefix("0x").unwrap_or(commitment)) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to decode commitment hex: {}", e);
            return VerificationResult {
                is_valid: false,
                details: vec![],
            };
        }
    };

    let mut all_valid = true;
    let mut details = Vec::new();

    for (idx, (proof_hex, dependency)) in proofs.clone().into_iter().enumerate() {
        debug!(
            "Verifying proof {} of {}: dependency '{}'",
            idx + 1,
            proofs.len(),
            dependency
        );
        debug!("Proof hex length: {}", proof_hex.len());

        // Decode proof hex string to bytes (strip optional 0x prefix)
        let proof_bytes = match hex::decode(proof_hex.strip_prefix("0x").unwrap_or(&proof_hex)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode proof hex: {}", e);
                all_valid = false;
                details.push(ProofVerificationDetail {
                    dependency: dependency.clone(),
                    is_member: false,
                    is_proof_valid: false,
                });
                continue;
            }
        };

        debug!(
            "Commitment bytes length: {}, Proof bytes length: {}",
            commitment_bytes.len(),
            proof_bytes.len()
        );

        // Call oZKS library via FFI, also extracting the key from the proof
        let mut proof_key = vec![0u8; 64]; // Keys are typically 32 bytes (H256)
        let mut proof_key_len: usize = proof_key.len();

        let result = unsafe {
            ffi::ozks_verify_proof(
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                proof_key.as_mut_ptr(),
                &mut proof_key_len,
            )
        };

        proof_key.truncate(proof_key_len);
        debug!("Proof key (hex): {}", hex::encode(&proof_key));

        // Verify the key in the proof matches the expected dependency
        let mut key_binding_valid = true;
        if !dependency.is_empty() {
            let expected_kv = hash_h256_kv(vec![&dependency]);
            let expected_key = expected_kv[0].0.as_bytes().to_vec();
            debug!("Expected key (hex): {}", hex::encode(&expected_key));

            if proof_key != expected_key {
                warn!(
                    "Key mismatch: proof key does not match expected key for dependency '{}'",
                    dependency
                );
                key_binding_valid = false;
                all_valid = false;
            } else {
                debug!("Key binding verified: proof key matches expected dependency key.");
            }
        } else {
            warn!("No dependency specified in proof file — skipping key binding check.");
        }

        let (is_member, is_proof_valid) = match result {
            0 => {
                debug!("Proof is valid and key is a member.");
                (true, true)
            }
            1 => {
                debug!("Proof is valid but key is NOT a member (non-inclusion proof verified).");
                (false, true)
            }
            2 => {
                warn!("Proof is NOT valid.");
                (false, false)
            }
            _ => {
                error!("Error during verification (code: {})", result);
                (false, false)
            }
        };

        if !is_proof_valid || !key_binding_valid {
            all_valid = false;
        }

        details.push(ProofVerificationDetail {
            dependency,
            is_member,
            is_proof_valid: is_proof_valid && key_binding_valid,
        });
    }

    VerificationResult {
        is_valid: all_valid,
        details,
    }
}

fn parse_proof_file(proof_path: &str) -> Result<Vec<(String, String)>, io::Error> {
    let path = Path::new(proof_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut proofs: Vec<(String, String)> = Vec::new();
    let mut current_proof = String::new();
    let mut current_dependency = String::new();

    for line_result in reader.lines() {
        let line = line_result?;
        let trimmed_line = line.trim();

        // Check for separator between proofs
        if trimmed_line == "---" {
            if !current_proof.is_empty() {
                proofs.push((current_proof.clone(), current_dependency.clone()));
                current_proof.clear();
                current_dependency.clear();
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
                "Dependency" => current_dependency = value,
                _ => debug!("Ignoring unknown key: {}", key),
            }
        } else {
            debug!("Ignoring line without key-value format: {}", trimmed_line);
        }
    }

    // Don't forget to add the last proof if it exists
    if !current_proof.is_empty() {
        proofs.push((current_proof, current_dependency));
    }

    Ok(proofs)
}
