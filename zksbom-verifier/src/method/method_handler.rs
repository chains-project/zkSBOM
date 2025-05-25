use crate::config::load_config;
use crate::method::merkle_patricia_trie::verify as verify_merkle_patricia_trie;
use crate::method::merkle_tree::verify as verify_merkle_tree;
#[cfg(target_arch = "x86_64")]
use crate::method::ozks::verify as verify_ozks;
use crate::method::sparse_merkle_tree::verify as verify_sparse_merkle_tree;
use log::debug;
#[cfg(target_arch = "aarch64")]
use log::error;
use std::str;
use std::time::{Duration, Instant};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn verify(commitment: &str, proof_path: &str, method: &str) -> bool {
    let config = load_config().unwrap();
    let is_timing_analysis = config.app.timing_analysis;

    match method {
        "merkle-tree" => {
            let is_valid;
            if is_timing_analysis {
                let now = Instant::now();
                is_valid = verify_merkle_tree(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-tree");
            } else {
                is_valid = verify_merkle_tree(commitment, proof_path);
            }
            debug!("Merkle Tree proof is valid: {}", is_valid);
            return is_valid;
        }
        "sparse-merkle-tree" => {
            let is_valid;
            if is_timing_analysis {
                let now = Instant::now();
                is_valid = verify_sparse_merkle_tree(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(elapsed, "sparse-merkle-tree");
            } else {
                is_valid = verify_sparse_merkle_tree(commitment, proof_path);
            }
            debug!("Sparse Merkle Tree proof is valid: {}", is_valid);
            return is_valid;
        }
        "merkle-patricia-trie" => {
            let is_valid;
            if is_timing_analysis {
                let now = Instant::now();
                is_valid = verify_merkle_patricia_trie(commitment, proof_path);
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-patricia-trie");
            } else {
                is_valid = verify_merkle_patricia_trie(commitment, proof_path);
            }
            debug!("Merkle Patricia Trie proof is valid: {}", is_valid);
            return is_valid;
        }
        "ozks" => {
            #[cfg(target_arch = "x86_64")]
            {
                let is_valid: bool;
                if is_timing_analysis {
                    let now = Instant::now();
                    is_valid = verify_ozks(commitment, proof_path);
                    let elapsed = now.elapsed();
                    print_timing(elapsed, "ozks");
                } else {
                    is_valid = verify_ozks(commitment, proof_path);
                }
                debug!("OZKS proof is valid: {}", is_valid);
                return is_valid;
            }

            #[cfg(target_arch = "aarch64")]
            {
                error!("Running on aarch64, oZKS is not supported");
                return false;
            }
        }
        _ => {
            panic!("Unknown method: {}", method);
        }
    }
}

fn print_timing(elapsed: Duration, method: &str) {
    let config = load_config().unwrap();
    let filename = config.app.timing_analysis_output;
    let path = Path::new(&filename);

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
