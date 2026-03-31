use crate::create_inclusion_proof::{
    test_create_inclusion_proof, test_create_inclusion_proof_dependency,
};
use crate::create_non_inclusion_proof::{
    test_create_non_inclusion_proof, test_create_non_inclusion_proof_dependency,
};
use crate::get_commitment::test_get_commitment;
use crate::upload_sbom::test_upload_sbom;

mod create_inclusion_proof;
mod create_non_inclusion_proof;
mod get_commitment;
mod upload_sbom;

#[test]
pub fn test_zksbom_workflow_cve() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    test_upload_sbom(sbom_path, config_path);
    test_get_commitment();
    test_create_inclusion_proof();
    test_create_non_inclusion_proof();
}

#[test]
pub fn test_zksbom_workflow_dependency() {
    let config_path = "./tests/config/config.toml";
    let sbom_path = "./tests/sboms/druid-0.22.0.cdx.json";
    test_upload_sbom(sbom_path, config_path);
    test_get_commitment();
    test_create_inclusion_proof_dependency();
    test_create_non_inclusion_proof_dependency();
}
