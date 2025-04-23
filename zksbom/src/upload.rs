use crate::check_dependencies_crates_io::check_dependencies;
use crate::config::load_config;
use crate::database::db_commitment::{insert_commitment, CommitmentDbEntry};
use crate::database::db_dependency::{insert_dependency, DependencyDbEntry};
use crate::database::db_sbom::{insert_sbom, SbomDbEntry};
use crate::github_advisory_database_mapping::MAPPINGS;
use crate::method::method_handler::create_commitment;
use log::{debug, error, warn};
use serde_json::{from_str, Value};

#[derive(Debug, Default)]
struct SbomParsed {
    vendor: String,
    product: String,
    version: String,
    dependencies: Vec<String>,
}

pub fn upload(_api_key: &str, sbom_path: &str) {
    debug!("Uploading SBOM...");

    // Step 1: Get the SBOM file content
    let sbom_content = get_file_content(&sbom_path);
    // debug!("SBOM Content: {}", &sbom_content);

    // Step 2: Parse SBOM file for dependencies, vendor, product, and version
    let parsed_sbom = parse_sbom(&sbom_content);
    debug!("Parsed SBOM: {:?}", parsed_sbom);

    let vendor = parsed_sbom.vendor;
    let product = parsed_sbom.product;
    let version = parsed_sbom.version;
    let dependencies: Vec<&str> = parsed_sbom
        .dependencies
        .iter()
        .map(|s| s.as_str())
        .collect();
    debug!(
        "Vendor: {}, Product: {}, Version: {}, dependencies: {:?}",
        vendor, product, version, dependencies
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
    let dependencies_clear_text = dependencies.clone();
    let commitment_dependencies = create_commitment(dependencies);
    let commitment = commitment_dependencies.0;
    let dependencies = commitment_dependencies.1;

    // Step 5: Save Commitment to database
    let commitment_entry = CommitmentDbEntry {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version.to_string(),
        commitment: commitment.to_string(),
    };

    insert_commitment(commitment_entry);

    // Step 6: Save dependencies to database
    let dependency_entry = DependencyDbEntry {
        dependencies: dependencies.join(","),
        commitment: commitment.to_string(),
        dependencies_clear_text: dependencies_clear_text.join(","),
    };

    insert_dependency(dependency_entry);
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
    let mut sbom_parsed = SbomParsed::default();

    // 2. Deserialize the JSON
    let json: Value = from_str(&json_str).expect("Failed to parse JSON");

    // 3. Extract component information
    if let Some(metadata) = json["metadata"].as_object() {
        if let Some(component) = metadata["component"].as_object() {
            let vendor = component
                .get("author")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mut product = component["name"].as_str().unwrap_or("unknown").to_string(); // Make product mutable
            let version = if product.contains(":") {
                let parts: Vec<&str> = product.split(":").collect();
                if parts.len() == 2 {
                    let product_name = parts[0].to_string();
                    let product_version = parts[1].to_string();
                    product = product_name;
                    product_version
                } else {
                    "unknown".to_string()
                }
            } else {
                component["version"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string()
            };

            debug!(
                "Vendor: {}, Product: {}, Version: {}",
                vendor, product, version
            );

            sbom_parsed.vendor = vendor;
            sbom_parsed.product = product;
            sbom_parsed.version = version;
        } else {
            error!("No component found in the metadata.");
        }
    } else {
        error!("No metadata found in the SBOM.");
    }

    // 4. Extract dependency information (if present)
    if let Some(components) = json["components"].as_array() {
        let mut all_dependencies = Vec::new();

        for component in components {
            debug!("Component: {:?}", component);
            if let (Some(name), Some(version)) =
                (component["name"].as_str(), component["version"].as_str())
            {
                let ecosystem = map_dependency_ecosystem(component["purl"].as_str().unwrap_or(""));
                all_dependencies.push(format!("{}@{}@{}", name, version, ecosystem));
            }
        }

        if all_dependencies.is_empty() {
            warn!("No components with name and version found in the SBOM.");
        }
        sbom_parsed.dependencies = all_dependencies.clone();

        // 5. Check dependencies
        let config = load_config().unwrap();
        if config.app.check_dependencies {
            check_dependencies(&all_dependencies);
        }
    } else {
        warn!("No components array found in the SBOM.");
    }

    sbom_parsed
}

fn map_dependency_ecosystem(purl: &str) -> String {
    let mut ecosystem = "unknown".to_string();
    // Try to extract the ecosystem from the purl
    if let Some(purl_ecosystem) = extract_ecosystem(purl) {
        debug!("Extracted ecosystem: {}", purl_ecosystem);
        for (key, value) in MAPPINGS.iter() {
            if purl_ecosystem.contains(key) {
                ecosystem = value.to_string(); // Update the ecosystem if a match is found
                break;
            }
        }
        debug!("Ecosystem: {}", ecosystem);
        return ecosystem; // Return the found ecosystem
    }

    // If no ecosystem is found, return "unknown"
    warn!("Could not extract ecosystem.");
    "unknown".to_string()
}

fn extract_ecosystem(purl: &str) -> Option<String> {
    if let Some(pkg_index) = purl.find("pkg:") {
        let start_index = pkg_index + "pkg:".len();
        if let Some(slash_index) = purl[start_index..].find('/') {
            return Some(purl[start_index..start_index + slash_index].to_string());
        }
    }
    None
}
