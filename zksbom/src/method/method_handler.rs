use crate::config::Config;
use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_patricia_trie::{
    create_commitment as create_merkle_patricia_trie_commitment,
    create_proof as create_merkle_patricia_trie_proof,
};
use crate::method::merkle_tree::{
    create_commitment as create_merkle_commitment, create_proof as create_merkle_proof,
};
use crate::method::ozks::{
    create_commitment as create_ozks_commitment, create_proof as create_ozks_proof,
};
use crate::method::sparse_merkle_tree::{
    create_commitment as create_sparse_merkle_commitment,
    create_proof as create_sparse_merkle_proof,
};
use log::{debug, error};
use std::str;
use std::time::{Duration, Instant};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn create_commitments(dependencies: Vec<&str>, config: &Config) -> Vec<String> {
    let is_timing_analysis = config.app.timing_analysis;

    // Merkle Tree
    debug!("Create Merkle Tree commitment");
    let merkle_tree_commitment: String;

    if is_timing_analysis {
        let now = Instant::now();
        merkle_tree_commitment = create_merkle_commitment(dependencies.clone());
        let elapsed = now.elapsed();
        print_timing(elapsed, "merkle-tree", config);
    } else {
        merkle_tree_commitment = create_merkle_commitment(dependencies.clone());
    }
    debug!("Merkle Tree Commitment: {}", merkle_tree_commitment);

    // Sparse Merkle Tree
    debug!("Create Sparse Merkle Tree commitment");
    let sparse_merkle_tree_commitment: String;

    if is_timing_analysis {
        let now = Instant::now();
        sparse_merkle_tree_commitment = create_sparse_merkle_commitment(dependencies.clone());
        let elapsed = now.elapsed();
        print_timing(elapsed, "sparse-merkle-tree", config);
    } else {
        sparse_merkle_tree_commitment = create_sparse_merkle_commitment(dependencies.clone());
    }
    debug!(
        "Sparse Merkle Tree Commitment: {}",
        sparse_merkle_tree_commitment
    );

    // Merkle Patricia Trie
    debug!("Create Merkle Patricia Trie commitment");
    let merkle_patricia_trie_commitment: String;

    if is_timing_analysis {
        let now = Instant::now();
        merkle_patricia_trie_commitment =
            create_merkle_patricia_trie_commitment(dependencies.clone());
        let elapsed = now.elapsed();
        print_timing(elapsed, "merkle-patricia-trie", config);
    } else {
        merkle_patricia_trie_commitment =
            create_merkle_patricia_trie_commitment(dependencies.clone());
    }
    debug!(
        "Merkle Patricia Trie Commitment: {}",
        merkle_patricia_trie_commitment
    );

    // oZKS
    debug!("Create oZKS commitment");
    let o_zks_commitment: String;

    if is_timing_analysis {
        let time_in_ms: String;
        (o_zks_commitment, time_in_ms) = create_ozks_commitment(dependencies.clone(), config);
        print_timing_ns(&time_in_ms, "oZKS", config);
    } else {
        (o_zks_commitment, _) = create_ozks_commitment(dependencies.clone(), config);
    }

    // Return all commitments
    vec![
        merkle_tree_commitment,
        sparse_merkle_tree_commitment,
        merkle_patricia_trie_commitment,
        o_zks_commitment,
    ]
}

pub fn get_commitment(
    vendor: &str,
    product: &str,
    version: &str,
    method: &str,
    config: &Config,
) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}, method: {}",
        vendor, product, version, method
    );

    let is_timing_analysis = config.app.timing_analysis;

    let commitment;
    match method {
        "merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_merkle_tree;
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-tree", config);
            } else {
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_merkle_tree;
            }
            debug!("Merkle Tree Commitment: {}", commitment);
        }
        "sparse-merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_sparse_merkle_tree;
                let elapsed = now.elapsed();
                print_timing(elapsed, "sparse-merkle-tree", config);
            } else {
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_sparse_merkle_tree;
            }
            debug!("Sparse Merkle Tree Commitment: {}", commitment);
        }
        "merkle-patricia-trie" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_merkle_patricia_trie;
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-patricia-trie", config);
            } else {
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_merkle_patricia_trie;
            }
            debug!("Merkle Patricia Trie Commitment: {}", commitment);
        }
        "ozks" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_ozks;
                let elapsed = now.elapsed();
                print_timing(elapsed, "oZKS", config);
            } else {
                commitment = get_db_commitment(
                    vendor.to_string(),
                    product.to_string(),
                    version.to_string(),
                    config,
                )
                .commitment_ozks;
            }
            debug!("oZKS Commitment: {}", commitment);
        }
        _ => {
            panic!("Unknown method: {}", method);
        }
    }

    return commitment;
}

pub fn create_proof(_api_key: &str, method: &str, commitment: &str, check: &str, config: &Config) {
    let is_timing_analysis = config.app.timing_analysis;

    match method {
        "merkle-tree" => {
            if is_timing_analysis {
                let time_in_ns = create_merkle_proof(commitment, check, config);
                print_timing_ns(&time_in_ns, "merkle-tree", config);
            } else {
                _ = create_merkle_proof(commitment, check, config);
            }
        }
        "sparse-merkle-tree" => {
            if is_timing_analysis {
                let time_in_ns = create_sparse_merkle_proof(commitment, check, config);
                print_timing_ns(&time_in_ns, "sparse-merkle-tree", config);
            } else {
                _ = create_sparse_merkle_proof(commitment, check, config);
            }
        }
        "merkle-patricia-trie" => {
            if is_timing_analysis {
                let time_in_ns = create_merkle_patricia_trie_proof(commitment, check, config);
                print_timing_ns(&time_in_ns, "merkle-patricia-trie", config);
            } else {
                create_merkle_patricia_trie_proof(commitment, check, config);
            }
        }
        "ozks" => {
            if is_timing_analysis {
                let time_in_ms: String;
                time_in_ms = create_ozks_proof(commitment, check, config);
                print_timing_ns(&time_in_ms, "oZKS", config);
            } else {
                _ = create_ozks_proof(commitment, check, config);
            }
        }
        _ => {
            error!("Unknown method: {}", method);
        }
    }
}

pub fn create_proof_no_commitment(
    _api_key: &str,
    method: &str,
    vendor: &str,
    product: &str,
    version: &str,
    check: &str,
    config: &Config,
) {
    let commitment = get_commitment(vendor, product, version, method, config);
    create_proof(_api_key, method, &commitment, check, config);
}

pub fn get_concealed_dependencies(dependency: &str) -> String {
    let concealed_dep = if dependency.contains('@') {
        let parts: Vec<&str> = dependency.split('@').collect();
        if parts.len() >= 2 {
            format!("{}@{}", parts.first().unwrap(), parts.last().unwrap())
        } else {
            error!("Problem parsing dependency: {}", dependency);
            dependency.to_string() // fallback to original
        }
    } else {
        error!("Problem parsing dependency: {}", dependency);
        dependency.to_string() // fallback to original
    };
    return concealed_dep;
}

fn print_timing(elapsed: Duration, method: &str, config: &Config) {
    let filename = &config.app.timing_analysis_output;
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

fn print_timing_ns(nanoseconds_str: &str, method: &str, config: &Config) {
    let nanoseconds = nanoseconds_str.parse::<u64>().unwrap();
    let seconds = nanoseconds as f64 / 1_000_000_000.0;

    let filename = &config.app.timing_analysis_output;
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

    _ = writeln!(file, "Method: {}, Elapsed: {:.10} seconds", method, seconds);
}
