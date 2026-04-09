use crate::create_inclusion_proof::test_create_inclusion_proof;
use crate::create_non_inclusion_proof::test_create_non_inclusion_proof;
use crate::get_commitment::test_get_commitment;
use crate::upload_sbom::test_upload_sbom;
use zksbom_operator::config::load_config_from_file;

mod create_inclusion_proof;
mod create_non_inclusion_proof;
mod get_commitment;
mod upload_sbom;

#[test]
pub fn test_zksbom_operator_workflow_cve() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    let config = load_config_from_file(config_path).unwrap();
    test_upload_sbom(sbom_path, config.clone());
    test_get_commitment(config.clone());
    test_create_inclusion_proof(config.clone());
    test_create_non_inclusion_proof(config);
}

#[test]
pub fn test_zksbom_operator_workflow_cve_concealed() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    let mut config = load_config_from_file(config_path).unwrap();
    config.app.conceal = true;
    test_upload_sbom(sbom_path, config.clone());
    test_get_commitment(config.clone());
    test_create_inclusion_proof(config.clone());
    test_create_non_inclusion_proof(config);
}

#[test]
pub fn test_zksbom_operator_workflow_dependency() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    let config = load_config_from_file(config_path).unwrap();
    test_upload_sbom(sbom_path, config.clone());
    test_get_commitment(config.clone());
    test_create_inclusion_proof(config.clone());
    test_create_non_inclusion_proof(config);
}

#[test]
pub fn test_zksbom_operator_workflow_dependency_concealed() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    let mut config = load_config_from_file(config_path).unwrap();
    config.app.conceal = true;
    test_upload_sbom(sbom_path, config.clone());
    test_get_commitment(config.clone());
    test_create_inclusion_proof(config.clone());
    test_create_non_inclusion_proof(config);
}
