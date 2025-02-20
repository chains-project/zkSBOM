use log::{debug, error};

use crate::database::db_sbom::{SbomDbEntry, insert_sbom};
use crate::database::db_commitment::{CommitmentDbEntry, insert_commitment};
use crate::database::db_vulnerability::{VulnerabilityDbEntry, insert_vulnerability};

use crate::method::method_handler::{create_commitment};




pub fn upload(api_key: &str, sbom_path: &str) {
    debug!("Uploading SBOM...");

    // Step 1: Get the SBOM file content
    let sbom_content = get_file_content(&sbom_path);
    debug!("SBOM Content: {}", &sbom_content);
    
    // Step 2: Parse SBOM file for vulnerabilities, vendor, product, and version
    // let parsed_sbom = parse_sbom(&sbom_content);
    let parsed_sbom = test(&sbom_content);

    
    let vendor = parsed_sbom.0;
    let product = parsed_sbom.1;
    let version = parsed_sbom.2;
    let vulnerabilities = parsed_sbom.3;

    // Step 3: Save SBOM to database
    let sbom_entry = SbomDbEntry {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version.to_string(),
        sbom: sbom_content.to_string(),
    };

    insert_sbom(sbom_entry);

    // Step 4: Generate Commitment
    let commitment_vulnerabilities = create_commitment(vulnerabilities);
    let commitment = commitment_vulnerabilities.0;
    let vulnerabilities = commitment_vulnerabilities.1;


    // Step 5: Save Commitment to database
    let commitment_entry = CommitmentDbEntry {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version.to_string(),
        commitment: commitment.to_string(),
    };

    insert_commitment(commitment_entry);

    // Step 6: Save vulnerabilities to database
    let vulnerability_entry = VulnerabilityDbEntry {
        vulnerabilities: vulnerabilities.join(","),
        commitment: commitment.to_string(),
    };

    insert_vulnerability(vulnerability_entry);
}

fn get_file_content(file_path: &str) -> String {
    let sbom_string = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read SBOM file: {}", e);
            panic!();
        }
    };

    sbom_string
}

fn parse_sbom(sbom_content: &str) -> (String, String, String, Vec<&str>) {
    //
    // "vendor": "aquasecurity",
    // "name": "trivy",
    // "version": "0.36.1"
    //
    let vendor = "vendor"; // TODO: Parse vendor from SBOM
    let product = "product"; // TODO: Parse product from SBOM
    let version = "version"; // TODO: Parse version from SBOM

    let vulnerabilities = vec![
        "vuln1", "vuln2", "vuln3", "vuln4",
        "vuln5", "vuln6", "vuln7", "vuln8",
    ]; // TODO: Parse vulnerabilities from SBOM

    (vendor.to_string(), product.to_string(), version.to_string(), vulnerabilities)
}
