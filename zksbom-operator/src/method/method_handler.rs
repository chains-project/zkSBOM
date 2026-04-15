use crate::config::Config;
use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::method::merkle_patricia_trie::create_commitment as create_merkle_patricia_trie_commitment;
use crate::method::merkle_tree::create_commitment as create_merkle_commitment;
use crate::method::ozks::create_commitment as create_ozks_commitment;
use crate::method::proof_handler::execute_proof_flow;
use crate::method::sparse_merkle_tree::create_commitment as create_sparse_merkle_commitment;
use log::debug;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn create_commitments(
    dependencies: Vec<&str>,
    metadata_leaf: String,
    config: &Config,
) -> Vec<String> {
    let is_timing_analysis = config.app.timing_analysis;
    let mut result: Vec<String> = vec![];

    if !config.app.only_ozks {
        let dependencies_with_metadata = {
            let mut d = dependencies.clone();
            d.push(metadata_leaf.as_str());
            d
        };

        // Merkle Tree
        debug!("Create Merkle Tree commitment");
        let merkle_tree_commitment = if is_timing_analysis {
            let now = Instant::now();
            let c = create_merkle_commitment(dependencies_with_metadata.clone());
            print_timing(now.elapsed(), "merkle-tree", config);
            c
        } else {
            create_merkle_commitment(dependencies_with_metadata.clone())
        };
        debug!("Merkle Tree Commitment: {}", merkle_tree_commitment);
        result.push(merkle_tree_commitment);

        // Sparse Merkle Tree
        debug!("Create Sparse Merkle Tree commitment");
        let sparse_merkle_tree_commitment = if is_timing_analysis {
            let now = Instant::now();
            let c = create_sparse_merkle_commitment(dependencies_with_metadata.clone());
            print_timing(now.elapsed(), "sparse-merkle-tree", config);
            c
        } else {
            create_sparse_merkle_commitment(dependencies_with_metadata.clone())
        };
        debug!(
            "Sparse Merkle Tree Commitment: {}",
            sparse_merkle_tree_commitment
        );
        result.push(sparse_merkle_tree_commitment);

        // Merkle Patricia Trie
        debug!("Create Merkle Patricia Trie commitment");
        let merkle_patricia_trie_commitment = if is_timing_analysis {
            let now = Instant::now();
            let c = create_merkle_patricia_trie_commitment(dependencies_with_metadata.clone());
            print_timing(now.elapsed(), "merkle-patricia-trie", config);
            c
        } else {
            create_merkle_patricia_trie_commitment(dependencies_with_metadata.clone())
        };
        debug!(
            "Merkle Patricia Trie Commitment: {}",
            merkle_patricia_trie_commitment
        );
        result.push(merkle_patricia_trie_commitment);
    }
    // oZKS
    debug!("Create oZKS commitment");
    let (o_zks_commitment, time_in_ns) = create_ozks_commitment(dependencies.clone(), config);
    if is_timing_analysis && !config.app.only_ozks {
        print_timing(
            Duration::from_nanos(time_in_ns.parse::<u64>().unwrap()),
            "oZKS",
            config,
        );
    }
    result.push(o_zks_commitment);

    result
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
    let now = Instant::now();

    let db_comm = get_db_commitment(
        vendor.to_string(),
        product.to_string(),
        version.to_string(),
        config,
    );

    let commitment = match method {
        "merkle-tree" => db_comm.commitment_merkle_tree,
        "sparse-merkle-tree" => db_comm.commitment_sparse_merkle_tree,
        "merkle-patricia-trie" => db_comm.commitment_merkle_patricia_trie,
        "ozks" => db_comm.commitment_ozks,
        _ => panic!("Unknown method: {}", method),
    };

    if is_timing_analysis {
        let name = if method == "ozks" { "oZKS" } else { method };
        print_timing(now.elapsed(), name, config);
    }

    debug!("{} Commitment: {}", method, commitment);
    commitment
}

pub fn create_proof(_api_key: &str, method: &str, commitment: &str, check: &str, config: &Config) {
    let start = Instant::now();
    let (dependency_count, query_db_time) = execute_proof_flow(method, commitment, check, config);
    let elapsed = start.elapsed().as_nanos();
    let elapsed_without_query_db_time = elapsed - query_db_time;

    if config.app.timing_analysis {
        print_timing_ns(
            elapsed_without_query_db_time.to_string().as_str(),
            method,
            dependency_count.as_str(),
            config,
        );
    }
}

pub fn create_proof_no_commitment(
    api_key: &str,
    method: &str,
    vendor: &str,
    product: &str,
    version: &str,
    check: &str,
    config: &Config,
) {
    let commitment = get_commitment(vendor, product, version, method, config);
    create_proof(api_key, method, &commitment, check, config);
}

fn print_timing(elapsed: Duration, method: &str, config: &Config) {
    let path = Path::new(&config.app.timing_analysis_output);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    let _ = writeln!(file, "{},{:.10}", method, elapsed.as_secs_f64());
}

pub fn print_timing_ns(nanoseconds_str: &str, method: &str, dep_count: &str, config: &Config) {
    if let Ok(nanoseconds) = nanoseconds_str.parse::<u64>() {
        let seconds = nanoseconds as f64 / 1_000_000_000.0;
        let path = Path::new(&config.app.timing_analysis_output);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        if dep_count != "" {
            let _ = writeln!(
                file,
                "{},{},{:.10}",
                method.to_lowercase(),
                seconds,
                dep_count
            );
        } else {
            let _ = writeln!(file, "{},{:.10}", method, seconds);
        }
    }
}
