use crate::config::Config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256_kv;
use crate::map_dependencies_vulnerabilities::{
    get_mapping_for_dependencies, get_vulnerable_packages_for_cve,
};
use log::{debug, error, info};
use reference_trie::NoExtensionLayout;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::str;
use std::time::Instant;
use trie_db::{
    proof::generate_proof as generate_proof_trie, DBValue, TrieDBMutBuilder, TrieLayout, TrieMut,
};

type MemoryDB<T> = memory_db::MemoryDB<
    <T as TrieLayout>::Hash,
    memory_db::HashKey<<T as TrieLayout>::Hash>,
    DBValue,
>;

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    debug!("Creating MPT commitment");
    let mut db = <MemoryDB<NoExtensionLayout>>::default();
    let mut root = Default::default();
    {
        let mut trie = <TrieDBMutBuilder<NoExtensionLayout>>::new(&mut db, &mut root).build();

        let kv_pairs = hash_h256_kv(dependencies);

        for kv_pair in kv_pairs {
            let key = kv_pair.0.as_bytes();
            let value = kv_pair.1.as_bytes();
            trie.insert(key, value).unwrap();
        }
    }

    debug!("MPT root: {:?}", &root);
    let commitment = format!("0x{}", hex::encode(root));
    debug!("MPT commitment hex: {}", commitment);

    return commitment;
}

fn generate_proof(
    commitment: String,
    dependencies: Vec<&str>,
    dependency: String,
    _: &Config,
) -> (String, String) {
    debug!("Generating proof for dependency: {}", dependency);
    debug!("Commitment: {}", commitment);

    let mut db = <MemoryDB<NoExtensionLayout>>::default();
    let mut root = Default::default();
    {
        let mut trie = <TrieDBMutBuilder<NoExtensionLayout>>::new(&mut db, &mut root).build();

        let kv_pairs = hash_h256_kv(dependencies);

        for kv_pair in kv_pairs {
            let key = kv_pair.0.as_bytes();
            let value = kv_pair.1.as_bytes();
            trie.insert(key, value).unwrap();
        }
    }

    if format!("0x{}", hex::encode(&root)) != commitment {
        panic!("Commitment mismatch MPT");
    }

    let kv = hash_h256_kv(vec![&dependency]);
    let key_u8 = kv.get(0).unwrap().0.as_bytes();
    let key = vec![key_u8];

    let now = Instant::now();
    let proof = generate_proof_trie::<_, NoExtensionLayout, _, _>(&db, &root, &key).unwrap();
    let elapsed = now.elapsed();

    let mut proof_hex = String::new();

    for proof_item in &proof {
        let proof_item_hex = format!("0x{};", hex::encode(proof_item));
        proof_hex.push_str(&proof_item_hex);
    }
    proof_hex = proof_hex.trim_end_matches(';').to_string();
    debug!("Proof hex: {}", proof_hex);

    return (proof_hex, elapsed.as_nanos().to_string());
}

pub fn create_proof(commitment: &str, check: &str, config: &Config) -> String {
    let dependency_entry = get_dependencies(commitment.to_string(), "merkle-patricia-trie", config);
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

    if let Err(e) = writeln!(file, "Leaf: {}", dependency) {
        error!("Error writing to file: {}", e);
        return "An error occurred printing the proof.".to_string();
    }

    if let Err(e) = writeln!(
        file,
        "# The Key is the Keccak-256 hash of the dependency string,\
    and the Value is the Keccak-256 hash of the same dependency string, both of which are used as\
    the key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing the\
    leaf dependency with the hash function."
    ) {
        error!("Error writing to file: {}", e);
        return "An error occurred printing the proof.".to_string();
    }

    let kv = hash_h256_kv(vec![&dependency]);
    let key = kv.get(0).unwrap().0;
    let value = kv.get(0).unwrap().1;

    let key_hex = format!("0x{}", hex::encode(key));
    let value_hex = format!("0x{}", hex::encode(value));

    if let Err(e) = writeln!(file, "Key: {}", key_hex) {
        error!("Error writing to file: {}", e);
        return "An error occurred printing the proof.".to_string();
    }

    if let Err(e) = writeln!(file, "Value: {}", value_hex) {
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

    format!("Proof written to: {}", output_path)
}
