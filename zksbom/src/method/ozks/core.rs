use super::{init_sqlite_storage, OZKSConfig, SQLiteBatchStorage, OZKS};
use crate::config::Config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256_kv;
use crate::map_dependencies_vulnerabilities::{
    get_mapping_for_dependencies, get_vulnerable_packages_for_cve,
};
use log::{debug, error, info};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

pub fn create_commitment(dependencies: Vec<&str>, config: &Config) -> (String, String) {
    info!("Creating oZKS commitment...");
    debug!("Dependencies: {:?}", dependencies);

    let now = Instant::now();

    let db_path = &config.db_ozks.path;

    // Ensure the parent directory exists
    if let Some(parent) = Path::new(&db_path).parent() {
        if !parent.exists() {
            if let Err(e) = create_dir_all(parent) {
                debug!("Error creating oZKS database directory: {}", e);
                return ("".to_string(), "".to_string());
            }
        }
    }

    // Initialize the C++ SQLite storage backend
    if let Err(e) = init_sqlite_storage(db_path.as_str()) {
        error!("Failed to initialize oZKS SQLite storage: {}", e);
        return ("".to_string(), "".to_string());
    }

    // Create Rust-side SQLite storage for manifest/metadata
    let storage = match SQLiteBatchStorage::new(db_path.as_str()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create SQLiteBatchStorage: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Create OZKS instance
    let ozks_config = OZKSConfig::new();
    let mut ozks = match OZKS::new(ozks_config, &storage) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to create OZKS instance: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Convert dependencies to key-value byte pairs
    let kv_pairs = hash_h256_kv(dependencies);
    debug!("Key-Value pairs: {:?}", kv_pairs);

    let batch: Vec<(Vec<u8>, Vec<u8>)> = kv_pairs
        .iter()
        .map(|(key, value)| (key.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect();

    // Insert batch into OZKS
    if let Err(e) = ozks.insert(&batch) {
        error!("Failed to insert batch into OZKS: {}", e);
        return ("".to_string(), "".to_string());
    }

    // Flush to storage
    if let Err(e) = ozks.flush() {
        error!("Failed to flush OZKS: {}", e);
        return ("".to_string(), "".to_string());
    }

    // Save OZKS metadata
    let serialized = match ozks.save() {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to save OZKS: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Persist metadata to SQLite
    if let Err(e) = storage.save_ozks_data(ozks.id(), &serialized) {
        error!("Failed to save OZKS data to SQLite: {}", e);
        return ("".to_string(), "".to_string());
    }

    // Get full serialized commitment (VRF public key + root hash)
    let commitment_serialized = match ozks.get_commitment_serialized() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get serialized OZKS commitment: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    let commitment_hex = hex::encode(&commitment_serialized);
    info!("oZKS Commitment (serialized): {}", commitment_hex);

    // Save instance manifest with commitment as the name (used for lookup during proof generation)
    let instance_index = storage.next_instance_index().unwrap_or(0);
    if let Err(e) = storage.save_instance_manifest(instance_index, ozks.id(), &commitment_hex) {
        error!("Failed to save instance manifest: {}", e);
        return ("".to_string(), "".to_string());
    }

    let elapsed = now.elapsed();
    let time_in_ns = elapsed.as_nanos().to_string();

    (commitment_hex, time_in_ns)
}

fn generate_proof(
    commitment: String,
    _dependencies: Vec<&str>,
    dependency: String,
    config: &Config,
) -> (String, String) {
    debug!(
        "Generating proof for dependency: {}; with commitment: {}",
        dependency, commitment
    );

    let now = Instant::now();

    let db_path = &config.db_ozks.path;

    // Initialize the C++ SQLite storage backend
    if let Err(e) = init_sqlite_storage(db_path.as_str()) {
        error!("Failed to initialize oZKS SQLite storage: {}", e);
        return ("".to_string(), "".to_string());
    }

    // Create Rust-side SQLite storage
    let storage = match SQLiteBatchStorage::new(db_path.as_str()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create SQLiteBatchStorage: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Find the trie_id by searching the manifest for the entry matching this commitment
    let manifest = match storage.load_instance_manifest() {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to load instance manifest: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    let trie_id = match manifest.iter().find(|(_, (_, name))| name == &commitment) {
        Some((_, (tid, _))) => *tid,
        None => {
            error!("No OZKS instance found for commitment: {}", commitment);
            return ("".to_string(), "".to_string());
        }
    };

    debug!("Found trie_id {} for commitment {}", trie_id, commitment);

    // Load OZKS metadata from SQLite
    let ozks_data = match storage.load_ozks_data(trie_id) {
        Ok(Some(data)) => data,
        Ok(None) => {
            error!("No OZKS data found for trie_id: {}", trie_id);
            return ("".to_string(), "".to_string());
        }
        Err(e) => {
            error!("Failed to load OZKS data: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Load OZKS instance from serialized data
    let (ozks, _) = match OZKS::load(&ozks_data, &storage) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to load OZKS instance: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    // Hash the dependency to get the key bytes
    let dep_kv_pair = hash_h256_kv(vec![&dependency]);
    let key_bytes = dep_kv_pair[0].0.as_bytes().to_vec();
    debug!("Query key: 0x{}", hex::encode(&key_bytes));

    // Query and get serialized proof (QueryResult)
    let proof_serialized = match ozks.query_proof(&key_bytes) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to query OZKS for proof: {}", e);
            return ("".to_string(), "".to_string());
        }
    };

    let proof = hex::encode(&proof_serialized);
    debug!("Serialized proof hex length: {}", proof.len());
    info!("Proof generated for dependency: {}", dependency);

    let elapsed = now.elapsed();
    let time_in_ns = elapsed.as_nanos().to_string();

    (proof, time_in_ns)
}

pub fn create_proof(commitment: &str, check: &str, config: &Config) -> String {
    let dependency_entry = get_dependencies(commitment.to_string(), "ozks", config);
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone(), config);

    let mut message = "".to_string();

    for dep in dependencies.clone() {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);

        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&check.to_string()) || stripped_dep == check {
                debug!(
                    "Dependency: {} is vulnerable to/in the SBOM: {}",
                    dep, check
                );

                // Get concealed dependency
                let concealed_dep = if dep.contains('@') {
                    let parts: Vec<&str> = dep.split('@').collect();
                    if parts.len() >= 2 {
                        format!("{}@{}", parts.first().unwrap(), parts.last().unwrap())
                    } else {
                        error!("Problem parsing dependency: {}", dep);
                        dep.to_string() // fallback to original
                    }
                } else {
                    error!("Problem parsing dependency: {}", dep);
                    dep.to_string() // fallback to original
                };

                let (proof, elapsed) = generate_proof(
                    commitment.to_string(),
                    dependencies,
                    concealed_dep.clone(),
                    config,
                );
                print_proof(proof, concealed_dep, false, config);
                println!("{message}");

                return elapsed;
            }
        }
    }

    // None-inclusion Proof:
    let dep_list: Vec<String>;

    if check.to_lowercase().starts_with("cve") {
        dep_list = get_vulnerable_packages_for_cve(check, &config);
    } else {
        dep_list = [check.to_string()].to_vec();
    }

    // Clear the output file before starting non-inclusion proofs
    let output_path = &config.app.output;
    if let Err(e) = File::create(output_path.as_str()) {
        debug!("Error creating output file for non-inclusion proofs, due to file not being there, that's fine: {}", e);
    }

    for dep in dep_list {
        info!("Dependency: {} is vulnerable/in the SBOM: {}", dep, check);

        let (proof, _) = generate_proof(
            commitment.to_string(),
            dependencies.clone(),
            dep.clone(),
            config,
        );
        message = print_proof(proof, dep, true, config);
    }

    println!("{message}");
    "".to_string()
}

fn print_proof(
    proof: String,
    dependency: String,
    is_non_inclusion: bool,
    config: &Config,
) -> String {
    let output_path = &config.app.output;

    let path = Path::new(&output_path);
    if let Some(parent) = path.parent() {
        if let Err(e) = create_dir_all(parent) {
            error!("Error creating directory: {}", e);
            return "An error occurred printing the proof.".to_string();
        }
    }

    let mut file = if is_non_inclusion {
        // For non-inclusion proofs, append to the file
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output_path)
        {
            Ok(file) => file,
            Err(e) => {
                error!("Error opening file for appending: {}", e);
                return "An error occurred printing the proof.".to_string();
            }
        }
    } else {
        // For inclusion proofs, create/overwrite the file
        match File::create(output_path.as_str()) {
            Ok(file) => file,
            Err(e) => {
                error!("Error creating file: {}", e);
                return "An error occurred printing the proof.".to_string();
            }
        }
    };

    if let Err(e) = writeln!(file, "Proof: {}", proof) {
        error!("Error writing to file: {}", e);
        return "An error occurred printing the proof.".to_string();
    }

    if let Err(e) = writeln!(file, "Dependency: {}", dependency) {
        error!("Error writing to file: {}", e);
        return "An error occurred printing the proof.".to_string();
    }

    // Add separator for non-inclusion proofs
    if is_non_inclusion {
        if let Err(e) = writeln!(file, "---") {
            error!("Error writing separator to file: {}", e);
            return "An error occurred printing the proof.".to_string();
        }
    }

    format!("Proof written to: {output_path}")
}
