use crate::create_inclusion_proof::{
    test_create_inclusion_proof, test_create_inclusion_proof_dependency,
};
use crate::create_non_inclusion_proof::{
    test_create_non_inclusion_proof, test_create_non_inclusion_proof_dependency,
};
use crate::get_commitment::test_get_commitment;
use crate::upload_sbom::test_upload_sbom;
use log::{debug, error};
use std::fs;
use std::path::Path;
use zksbom::config::load_config_from_file;

mod create_inclusion_proof;
mod create_non_inclusion_proof;
mod get_commitment;
mod upload_sbom;

#[test]
pub fn test_zksbom_workflow_cve() {
    let config_path = "./tests/config/config.toml";
    test_upload_sbom(config_path);
    test_get_commitment();
    test_create_inclusion_proof();
    test_create_non_inclusion_proof();
    clean_up(config_path)
}

#[test]
pub fn test_zksbom_workflow_dependency() {
    let config_path = "./tests/config/config.toml";
    test_upload_sbom(config_path);
    test_get_commitment();
    test_create_inclusion_proof_dependency();
    test_create_non_inclusion_proof_dependency();
    clean_up(config_path)
}

fn clean_up(config_path: &str) {
    let config = load_config_from_file(config_path).unwrap();

    let output_path = Path::new(&config.app.output);
    if let Some(parent) = output_path.parent() {
        match fs::remove_dir_all(parent) {
            Ok(_) => debug!("Deleted parent directory: {:?}", parent),
            Err(e) => error!("Failed to delete parent directory: {}", e),
        }
    }

    let db_paths = [
        &config.db_commitment.path,
        &config.db_dependency.path,
        &config.db_ozks.path,
    ];

    for db_path in db_paths {
        let output_path = Path::new(&db_path);
        if let Some(parent) = output_path.parent() {
            match fs::remove_dir_all(parent) {
                Ok(_) => debug!("Deleted parent directory: {:?}", parent),
                Err(e) => error!("Failed to delete parent directory: {}", e),
            }
        }
    }
}
