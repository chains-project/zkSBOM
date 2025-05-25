use crate::config::load_config;
use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_patricia_trie::{
    create_commitment as create_merkle_patricia_trie_commitment,
    create_proof as create_merkle_patricia_trie_proof,
};
use crate::method::merkle_tree::{
    create_commitment as create_merkle_commitment, create_proof as create_merkle_proof,
};
#[cfg(target_arch = "x86_64")]
use crate::method::ozks::{
    create_commitment as create_ozks_commitment, create_proof as create_ozks_proof,
};
use crate::method::sparse_merkle_tree::{
    create_commitment as create_sparse_merkle_commitment,
    create_proof as create_sparse_merkle_proof,
};

#[cfg(target_arch = "aarch64")]
use log::warn;
use log::{debug, error};
use std::str;
use std::time::{Duration, Instant};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub fn create_commitments(dependencies: Vec<&str>) -> Vec<String> {
    let config = load_config().unwrap();
    let is_timing_analysis = config.app.timing_analysis;

    // Merkle Tree
    debug!("Create Merkle Tree commitment");
    let merkle_tree_commitment: String;

    if is_timing_analysis {
        let now = Instant::now();
        merkle_tree_commitment = create_merkle_commitment(dependencies.clone());
        let elapsed = now.elapsed();
        print_timing(elapsed, "merkle-tree");
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
        print_timing(elapsed, "sparse-merkle-tree");
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
        print_timing(elapsed, "merkle-patricia-trie");
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

    #[cfg(target_arch = "x86_64")]
    {
        debug!("Running on x86_64");
        if is_timing_analysis {
            let now = Instant::now();
            o_zks_commitment = create_ozks_commitment(dependencies.clone());
            let elapsed = now.elapsed();
            print_timing(elapsed, "oZKS");
        } else {
            o_zks_commitment = create_ozks_commitment(dependencies.clone());
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        warn!("Running on aarch64, oZKS is not supported");
        o_zks_commitment = String::from("oZKS not supported on aarch64 architecture");
    }

    // Return all commitments
    return vec![
        merkle_tree_commitment,
        sparse_merkle_tree_commitment,
        merkle_patricia_trie_commitment,
        o_zks_commitment,
    ];
}

pub fn get_commitment(vendor: &str, product: &str, version: &str, method: &str) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}, method: {}",
        vendor, product, version, method
    );

    let config = load_config().unwrap();
    let is_timing_analysis = config.app.timing_analysis;

    let commitment;
    match method {
        "merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_merkle_tree;
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-tree");
            } else {
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_merkle_tree;
            }
            debug!("Merkle Tree Commitment: {}", commitment);
        }
        "sparse-merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_sparse_merkle_tree;
                let elapsed = now.elapsed();
                print_timing(elapsed, "sparse-merkle-tree");
            } else {
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_sparse_merkle_tree;
            }
            debug!("Sparse Merkle Tree Commitment: {}", commitment);
        }
        "merkle-patricia-trie" => {
            if is_timing_analysis {
                let now = Instant::now();
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_merkle_patricia_trie;
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-patricia-trie");
            } else {
                commitment =
                    get_db_commitment(vendor.to_string(), product.to_string(), version.to_string())
                        .commitment_merkle_patricia_trie;
            }
            debug!("Merkle Patricia Trie Commitment: {}", commitment);
        }
        "ozks" => {
            #[cfg(target_arch = "x86_64")]
            {
                if is_timing_analysis {
                    let now = Instant::now();
                    commitment = get_db_commitment(
                        vendor.to_string(),
                        product.to_string(),
                        version.to_string(),
                    )
                    .commitment_ozks;
                    let elapsed = now.elapsed();
                    print_timing(elapsed, "oZKS");
                } else {
                    commitment = get_db_commitment(
                        vendor.to_string(),
                        product.to_string(),
                        version.to_string(),
                    )
                    .commitment_ozks;
                }
                debug!("oZKS Commitment: {}", commitment);
            }

            #[cfg(target_arch = "aarch64")]
            {
                warn!("Running on aarch64, oZKS is not supported");
                commitment = String::from("oZKS not supported on aarch64 architecture");
            }
        }
        _ => {
            panic!("Unknown method: {}", method);
        }
    }

    return commitment;
}

pub fn get_zkp(_api_key: &str, method: &str, commitment: &str, vulnerability: &str) {
    let config = load_config().unwrap();
    let is_timing_analysis = config.app.timing_analysis;

    match method {
        "merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                create_merkle_proof(commitment, vulnerability);
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-tree");
            } else {
                create_merkle_proof(commitment, vulnerability);
            }
        }
        "sparse-merkle-tree" => {
            if is_timing_analysis {
                let now = Instant::now();
                create_sparse_merkle_proof(commitment, vulnerability);
                let elapsed = now.elapsed();
                print_timing(elapsed, "sparse-merkle-tree");
            } else {
                create_sparse_merkle_proof(commitment, vulnerability);
            }
        }
        "merkle-patricia-trie" => {
            if is_timing_analysis {
                let now = Instant::now();
                create_merkle_patricia_trie_proof(commitment, vulnerability);
                let elapsed = now.elapsed();
                print_timing(elapsed, "merkle-patricia-trie");
            } else {
                create_merkle_patricia_trie_proof(commitment, vulnerability);
            }
        }
        "ozks" => {
            #[cfg(target_arch = "x86_64")]
            {
                if is_timing_analysis {
                    let now = Instant::now();
                    create_ozks_proof(commitment, vulnerability);
                    let elapsed = now.elapsed();
                    print_timing(elapsed, "oZKS");
                } else {
                    create_ozks_proof(commitment, vulnerability);
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                warn!("Running on aarch64, oZKS is not supported");
            }
        }
        _ => {
            error!("Unknown method: {}", method);
        }
    }
}

pub fn get_zkp_full(
    _api_key: &str,
    method: &str,
    vendor: &str,
    product: &str,
    version: &str,
    vulnerability: &str,
) {
    let commitment = get_commitment(vendor, product, version, method);
    get_zkp(_api_key, method, &commitment, vulnerability);
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
