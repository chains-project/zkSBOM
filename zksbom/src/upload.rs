use log::{debug, error, warn, info};

use crate::database::db_commitment::{insert_commitment, CommitmentDbEntry};
use crate::database::db_sbom::{insert_sbom, SbomDbEntry};
use crate::database::db_vulnerability::{insert_vulnerability, VulnerabilityDbEntry};

use crate::method::method_handler::create_commitment;

use serde_json::{from_str, Value};
use std::fs::File;
use std::io::Read;

#[derive(Debug, Default)]
struct SbomParsed {
    vendor: String,
    product: String,
    version: String,
    vulnerabilities: Vec<String>,
}

pub fn upload(api_key: &str, sbom_path: &str) {
    debug!("Uploading SBOM...");

    // Step 1: Get the SBOM file content
    let sbom_content = get_file_content(&sbom_path);
    // debug!("SBOM Content: {}", &sbom_content);

    // Step 2: Parse SBOM file for vulnerabilities, vendor, product, and version
    let parsed_sbom = parse_sbom(&sbom_content);
    debug!("Parsed SBOM: {:?}", parsed_sbom);

    let vendor = parsed_sbom.vendor;
    let product = parsed_sbom.product;
    let version = parsed_sbom.version;
    let vulnerabilities: Vec<&str> = parsed_sbom
        .vulnerabilities
        .iter()
        .map(|s| s.as_str())
        .collect();
    debug!(
        "Vendor: {}, Product: {}, Version: {}, Vulnerabilities: {:?}",
        vendor, product, version, vulnerabilities
    );

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

fn parse_sbom(sbom_content: &str) -> SbomParsed {
    let json_str = sbom_content;
    let mut sbom_parsed = SbomParsed::default(); // Initialize with default values

    // 2. Deserialize the JSON
    let json: Value = from_str(&json_str).expect("Failed to parse JSON");

    // 3. Extract component information
    if let Some(components) = json["components"].as_array() {
        if let Some(metadata) = json["metadata"].as_object() {
            if let Some(tools) = metadata["tools"].as_array() {
                for tool in tools {
                    let vendor = tool["vendor"].as_str().unwrap_or("unknown").to_string();
                    let product = tool["name"].as_str().unwrap_or("unknown").to_string();
                    let version = tool["version"].as_str().unwrap_or("unknown").to_string();

                    debug!(
                        "  Vendor: {}, Product: {}, Version: {}",
                        vendor, product, version
                    );

                    // Store the LAST tool's info.  If you need all, use a Vec<ToolInfo>
                    sbom_parsed.vendor = vendor;
                    sbom_parsed.product = product;
                    sbom_parsed.version = version;
                }
            } else {
                error!("No tools found in the metadata.");
            }
        } else {
            error!("No metadata found in the SBOM.");
        }
    } else {
        error!("No components array found in the SBOM."); // Handle missing components
    }

    // 4. Extract vulnerability information (if present)
    if let Some(vulnerabilities) = json["vulnerabilities"].as_array() {
        let mut all_vulnerabilities = Vec::new();

        for vulnerability in vulnerabilities {
            if let Some(id) = vulnerability["id"].as_str() {
                all_vulnerabilities.push(id.to_string());
            }
        }

        if !all_vulnerabilities.is_empty() {
            debug!("Vulnerabilities: {}", all_vulnerabilities.join(", "));
        } else {
            error!("No vulnerabilities found.");
        }
        sbom_parsed.vulnerabilities = all_vulnerabilities; // Store vulnerabilities
    } else {
        warn!("No vulnerabilities array found in the SBOM. This might be because there are no vulnerabilities in the SBOM.");
    }

    sbom_parsed // Return the populated struct
}
