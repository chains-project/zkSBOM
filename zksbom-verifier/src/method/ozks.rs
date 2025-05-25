use crate::hasher::hash_h256_kv;
use hex;
use log::{debug, error, warn};
use sp_core::H256;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;

pub fn verify(commitment: &str, proof_path: &str) -> bool {
    let is_valid = false;
    debug!("Commitment: {}, Proof Path: {}", commitment, proof_path);

    let (proof, dependency) = parse_proof_file(proof_path).unwrap();

    debug!("Proof: {:?}", proof);
    debug!("Dependency: {:?}", dependency);

    // Get key of dependency
    let dep_kv_pair: Vec<(H256, H256)> = hash_h256_kv(vec![&dependency]);
    debug!("Dependency Key-Value pair: {:?}", dep_kv_pair);
    let key_hex = format!("0x{}", hex::encode(dep_kv_pair[0].0));
    let key_bytes = hex::decode(key_hex.strip_prefix("0x").unwrap()).unwrap();
    let hex_bytes_string = format!("{:?}", key_bytes);

    let dependency_key = hex_bytes_string.clone();
    debug!("Dependency Key: {}", dependency_key);

    let output = Command::new("./src/method/ozks/ozks-verifier.exe")
        .args(["verify", &commitment, &proof, &dependency_key])
        .output()
        .expect("Failed to run process");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    debug!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    debug!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    let parts: Vec<&str> = stdout_str.trim().split_whitespace().collect();

    if parts.len() >= 2 {
        let proof_for_commitment = parts[0].to_lowercase().parse::<bool>().unwrap_or(false); // Default to false if parsing fails
        let proof_key_is_member = parts[1].to_lowercase().parse::<bool>().unwrap_or(false); // Default to false if parsing fails

        debug!("proof_for_commitment: {}", proof_for_commitment);
        debug!("proof_key_is_member: {}", proof_key_is_member);

        if proof_for_commitment && proof_key_is_member {
            debug!("Proof is valid for commitment and key is a member of the dependency.");
            return true;
        } else {
            warn!("Proof is NOT valid for commitment or key is NOT a member of the dependency.");
        }
    } else {
        error!("Error: Not enough boolean values in stdout to split.");
    }

    return is_valid;
}

fn parse_proof_file(proof_path: &str) -> Result<(String, String), io::Error> {
    let path = Path::new(proof_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut proof = String::new();
    let mut dependency = String::new();

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
                "Proof" => proof = value,
                "Dependency" => dependency = value,
                _ => error!("Warning: Unknown key: {}", key), // Handle unknown keys
            }
        } else {
            error!("Warning: Invalid line format: {}", trimmed_line);
        }
    }

    Ok((proof, dependency))
}
