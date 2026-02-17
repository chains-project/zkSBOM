use crate::config::AppConfig;
use crate::method::merkle_patricia_trie::{
    verify as verify_merkle_patricia_trie, VerificationResult as MPTVerificationResult,
};
use crate::method::merkle_tree::verify as verify_merkle_tree;
use crate::method::ozks::{verify as verify_ozks, VerificationResult as OZKSVerificationResult};
use crate::method::sparse_merkle_tree::{
    verify as verify_sparse_merkle_tree, VerificationResult as SMTVerificationResult,
};
use log::debug;
use std::str;
use std::time::{Duration, Instant};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn verify_ozks_detailed(
    commitment: &str,
    proof_path: &str,
    app_config: &AppConfig,
) -> OZKSVerificationResult {
    let is_timing_analysis = app_config.timing_analysis;

    let result;
    if is_timing_analysis {
        let now = Instant::now();
        result = verify_ozks(commitment, proof_path);
        let elapsed = now.elapsed();
        print_timing(elapsed, "ozks", &app_config.timing_analysis_output);
    } else {
        result = verify_ozks(commitment, proof_path);
    }
    debug!(
        "OZKS proof verification complete: is_valid={}",
        result.is_valid
    );
    result
}

pub fn verify_sparse_merkle_tree_detailed(
    commitment: &str,
    proof_path: &str,
    app_config: &AppConfig,
) -> SMTVerificationResult {
    let is_timing_analysis = app_config.timing_analysis;

    let result;
    if is_timing_analysis {
        let now = Instant::now();
        result = verify_sparse_merkle_tree(commitment, proof_path);
        let elapsed = now.elapsed();
        print_timing(
            elapsed,
            "sparse-merkle-tree",
            &app_config.timing_analysis_output,
        );
    } else {
        result = verify_sparse_merkle_tree(commitment, proof_path);
    }
    debug!(
        "Sparse Merkle Tree proof verification complete: is_valid={}",
        result.is_valid
    );
    result
}

pub fn verify_merkle_patricia_trie_detailed(
    commitment: &str,
    proof_path: &str,
    app_config: &AppConfig,
) -> MPTVerificationResult {
    let is_timing_analysis = app_config.timing_analysis;

    let result;
    if is_timing_analysis {
        let now = Instant::now();
        result = verify_merkle_patricia_trie(commitment, proof_path);
        let elapsed = now.elapsed();
        print_timing(
            elapsed,
            "merkle-patricia-trie",
            &app_config.timing_analysis_output,
        );
    } else {
        result = verify_merkle_patricia_trie(commitment, proof_path);
    }
    debug!(
        "Merkle Patricia Trie proof verification complete: is_valid={}",
        result.is_valid
    );
    result
}

pub fn verify(commitment: &str, proof_path: &str, method: &str, app_config: &AppConfig) -> bool {
    let is_timing_analysis = app_config.timing_analysis;

    match method {
        "merkle-tree" => {
            let is_valid;
            if is_timing_analysis {
                let now = Instant::now();
                is_valid = verify_merkle_tree(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-tree", &app_config.timing_analysis_output);
            } else {
                is_valid = verify_merkle_tree(commitment, proof_path);
            }
            debug!("Merkle Tree proof is valid: {}", is_valid);
            return is_valid;
        }
        "sparse-merkle-tree" => {
            let result;
            if is_timing_analysis {
                let now = Instant::now();
                result = verify_sparse_merkle_tree(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(
                    elapsed,
                    "sparse-merkle-tree",
                    &app_config.timing_analysis_output,
                );
            } else {
                result = verify_sparse_merkle_tree(commitment, proof_path);
            }
            debug!("Sparse Merkle Tree proof is valid: {}", result.is_valid);
            return result.is_valid;
        }
        "merkle-patricia-trie" => {
            let result;
            if is_timing_analysis {
                let now = Instant::now();
                result = verify_merkle_patricia_trie(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(
                    elapsed,
                    "merkle-patricia-trie",
                    &app_config.timing_analysis_output,
                );
            } else {
                result = verify_merkle_patricia_trie(commitment, proof_path);
            }
            debug!("Merkle Patricia Trie proof is valid: {}", result.is_valid);
            return result.is_valid;
        }
        "ozks" => {
            let result = verify_ozks_detailed(commitment, proof_path, app_config);
            return result.is_valid;
        }
        _ => {
            panic!("Unknown method: {}", method);
        }
    }
}

fn print_timing(elapsed: Duration, method: &str, timing_output_path: &str) {
    let path = Path::new(timing_output_path);

    // Check if the directory exists, and create it if not
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            _ = fs::create_dir_all(parent);
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();

    let seconds = elapsed.as_secs_f64();
    _ = writeln!(file, "Method: {}, Elapsed: {:.5} seconds", method, seconds);
}
