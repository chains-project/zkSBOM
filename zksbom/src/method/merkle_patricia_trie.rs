use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::hasher::hash_h256_kv;
use crate::map_dependencies_vulnerabilities::get_mapping_for_dependencies;
use log::{debug, error};
use reference_trie::NoExtensionLayout;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::str;
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

fn generate_proof(commitment: String, dependencies: Vec<&str>, dependency: String) -> String {
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

    let proof = generate_proof_trie::<_, NoExtensionLayout, _, _>(&db, &root, &key).unwrap();

    let mut proof_hex = String::new();

    for proof_item in &proof {
        let proof_item_hex = format!("0x{};", hex::encode(proof_item));
        proof_hex.push_str(&proof_item_hex);
    }
    proof_hex = proof_hex.trim_end_matches(';').to_string();
    debug!("Proof hex: {}", proof_hex);

    return proof_hex;
}

pub fn create_proof(commitment: &str, vulnerability: &str) {
    let dependency_entry = get_dependencies(commitment.to_string(), "merkle-patricia-trie");
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone());

    for dep in dependencies.clone() {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);
        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&vulnerability.to_string()) {
                debug!("Dependency: {} is vulnerable to: {}", dep, vulnerability);
                let proof = generate_proof(commitment.to_string(), dependencies, dep.to_string());
                print_proof(proof, dep.to_string());

                break; // Break the loop after finding the first match
            }
        }
    }
}

fn print_proof(proof: String, dependency: String) {
    let config = load_config().unwrap();
    let output_path = config.app.output;

    let path = Path::new(&output_path);
    if let Some(parent) = path.parent() {
        if let Err(e) = create_dir_all(parent) {
            error!("Error creating directory: {}", e);
            return;
        }
    }

    let mut file = match File::create(&output_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error creating file: {}", e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "Proof: {}", proof) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "Leaf: {}", dependency) {
        error!("Error writing to file: {}", e);
        return;
    }

    // TODO: Describe
    if let Err(e) = writeln!(file, "# TODO: Describe") {
        error!("Error writing to file: {}", e);
        return;
    }

    let kv = hash_h256_kv(vec![&dependency]);
    let key = kv.get(0).unwrap().0;
    let value = kv.get(0).unwrap().1;

    let key_hex = format!("0x{}", hex::encode(key));
    let value_hex = format!("0x{}", hex::encode(value));

    if let Err(e) = writeln!(file, "Key: {}", key_hex) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "Value: {}", value_hex) {
        error!("Error writing to file: {}", e);
        return;
    }

    println!("Proof written to: {}", output_path);
}
