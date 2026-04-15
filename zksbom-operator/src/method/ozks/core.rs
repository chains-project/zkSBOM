use super::{init_sqlite_storage, OZKSConfig, SQLiteBatchStorage, OZKS};
use crate::config::Config;
use crate::hasher::hash_h256_kv;
use log::{error, info};
use std::fs::create_dir_all;
use std::path::Path;
use std::time::Instant;

pub fn create_commitment(dependencies: Vec<&str>, config: &Config) -> (String, String) {
    info!("Creating oZKS commitment...");
    let now = Instant::now();
    let db_path = &config.db_ozks.path;

    if let Some(parent) = Path::new(&db_path).parent() {
        if !parent.exists() {
            let _ = create_dir_all(parent);
        }
    }

    if let Err(e) = init_sqlite_storage(db_path.as_str()) {
        error!("Failed to init sqlite: {}", e);
        return ("".to_string(), "".to_string());
    }

    let storage = SQLiteBatchStorage::new(db_path.as_str()).unwrap();
    let ozks_config = OZKSConfig::new();
    let mut ozks = OZKS::new(ozks_config, &storage).unwrap();

    let batch: Vec<(Vec<u8>, Vec<u8>)> = hash_h256_kv(dependencies)
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();

    ozks.insert(&batch).unwrap();
    ozks.flush().unwrap();

    let serialized = ozks.save().unwrap();
    storage.save_ozks_data(ozks.id(), &serialized).unwrap();

    let commitment_hex = hex::encode(&ozks.get_commitment_serialized().unwrap());
    let instance_index = storage.next_instance_index().unwrap_or(0);
    storage
        .save_instance_manifest(instance_index, ozks.id(), &commitment_hex)
        .unwrap();

    let elapsed = now.elapsed().as_nanos().to_string();
    (commitment_hex, elapsed)
}

pub fn generate_formatted_proof(
    commitment: &str,
    _dependencies: Vec<&str>, // oZKS pulls from DB, so we don't rebuild the tree in memory
    dependency: &str,
    config: &Config,
) -> String {
    let db_path = &config.db_ozks.path;

    init_sqlite_storage(db_path.as_str()).unwrap();
    let storage = SQLiteBatchStorage::new(db_path.as_str()).unwrap();
    let manifest = storage.load_instance_manifest().unwrap();

    let trie_id = manifest
        .iter()
        .find(|(_, (_, name))| name == commitment)
        .unwrap()
        .1
         .0;
    let ozks_data = storage.load_ozks_data(trie_id).unwrap().unwrap();
    let (ozks, _) = OZKS::load(&ozks_data, &storage).unwrap();

    let key_bytes = hash_h256_kv(vec![dependency])[0].0.as_bytes().to_vec();
    let proof_serialized = ozks.query_proof(&key_bytes).unwrap();

    let proof_hex = hex::encode(&proof_serialized);
    let formatted_payload = format!("Proof: {}\nDependency: {}", proof_hex, dependency);

    formatted_payload
}
