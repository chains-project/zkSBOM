use chrono::format::parse;
use crate::check_dependencies_crates_io::check_dependencies;
use crate::config::Config;
use crate::database::db_commitment::{insert_commitment, CommitmentDbEntry};
use crate::database::db_dependency::{insert_dependency, DependencyDbEntry};
use crate::github_advisory_database_mapping::MAPPINGS;
use crate::method::method_handler::create_commitments;
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use rand::distr::Alphanumeric;
use rand::Rng;
use regex::Regex;
use serde_json::{from_str, Value};

#[derive(Debug, Default)]
struct SbomParsed {
    vendor: String,
    product: String,
    version: String,
    dependencies: Vec<String>,
}

pub fn upload(_api_key: &str, sbom_path: &str, config: &Config) {
    debug!("Uploading SBOM with path: {sbom_path}");

    // Get the SBOM file content
    let sbom_content = get_file_content(&sbom_path);

    // Parse SBOM file for dependencies, vendor, product, and version
    let parsed_sbom = parse_sbom(&sbom_content, config);
    debug!("Parsed SBOM: {:?}", parsed_sbom);

    let vendor = parsed_sbom.vendor;
    let product = parsed_sbom.product;
    let version = parsed_sbom.version;

    let mut leaves: Vec<String> = vec![];

    // Add dependencies to the list of leaves
    leaves.extend(parsed_sbom.dependencies.iter().map(|s| s.to_string()));

    debug!(
        "Vendor: {}, Product: {}, Version: {}, leaves: {:?}",
        vendor, product, version, leaves
    );

    // Add concealed dependency to list of leaves
    let mut concealed_dependency = Vec::new();
    for dependency in &leaves {
        let parts: Vec<&str> = dependency.split('@').collect();

        // Keep first and last parts, join with '@'
        if parts.len() >= 2 {
            let result = format!("{}@{}", parts.first().unwrap(), parts.last().unwrap());
            concealed_dependency.push(result);
        } else {
            error!("Problem parsing dependency: {}", dependency);
        }
    }

    // Remove duplicates in concealed dependencies, for that we must sort first.
    concealed_dependency.sort();
    concealed_dependency.dedup();

    // Append the new prefixes to the original list
    leaves.extend(concealed_dependency);
    debug!("Leaves with concealed dependencies: {:?}", leaves);

    // Metadata leaf, only used for MT, SMT, MPT
    let metadata_leaf: String = format!("{};{};v{}", vendor.to_string(), &product, &version);

    // Generate Commitments
    let commitments = create_commitments(
        leaves.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
        metadata_leaf.clone(),
        config,
    );
    let commitment_merkle_tree = commitments[0].clone();
    let commitment_sparse_merkle_tree = commitments[1].clone();
    let commitment_merkle_patricia_trie = commitments[2].clone();
    let commitment_ozks = commitments[3].clone();

    // Save Commitments to database
    let commitment_entry = CommitmentDbEntry {
        vendor: vendor,
        product: product,
        version: version,
        commitment_merkle_tree: commitment_merkle_tree.clone(),
        commitment_sparse_merkle_tree: commitment_sparse_merkle_tree.clone(),
        commitment_merkle_patricia_trie: commitment_merkle_patricia_trie.clone(),
        commitment_ozks: commitment_ozks.clone(),
    };
    insert_commitment(commitment_entry, config);

    // Save leaves to database
    let dependency_entry = DependencyDbEntry {
        commitment_merkle_tree,
        commitment_sparse_merkle_tree,
        commitment_merkle_patricia_trie,
        commitment_ozks,
        dependencies: leaves.join(","),
        metadata: metadata_leaf,
    };
    insert_dependency(dependency_entry, config);

    println!("Uploading SBOM completed.")
}

fn get_file_content(file_path: &str) -> String {
    let sbom_string = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to read SBOM file: {}", e);
            panic!();
        }
    };

    return sbom_string;
}

fn parse_sbom(sbom_content: &str, config: &Config) -> SbomParsed {
    let json_str = sbom_content;
    let mut sbom_parsed = SbomParsed::default();

    // Deserialize the JSON
    let json: Value = from_str(&json_str).expect("Failed to parse JSON");

    // Extract component information
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

    // Extract dependency information (if present)
    if let Some(components) = json["components"].as_array() {
        let mut all_dependencies = Vec::new();

        for component in components {
            debug!("Component: {:?}", component);
            let parsed_purl = parse_purl(component["purl"].as_str().unwrap_or("")).unwrap();

            let mut name = parsed_purl.name;
            if !parsed_purl.namespace.is_none() {
                name = format!("{}/{}", parsed_purl.namespace.unwrap(), name);
            }
            all_dependencies.push(format!("{}@{}@{}", name, parsed_purl.version.unwrap(), parsed_purl.pkg_type));
        }

        if all_dependencies.is_empty() {
            warn!("No components with name and version found in the SBOM.");
        }
        sbom_parsed.dependencies = all_dependencies.clone();

        // Check dependencies
        if config.app.check_dependencies {
            check_dependencies(&all_dependencies, config);
        }
    } else {
        warn!("No components array found in the SBOM.");
    }

    sbom_parsed
}

fn create_salt() -> String {
    let salt: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64) // length of salt
        .map(char::from)
        .collect();
    return salt;
}

#[allow(dead_code)]
/// Parsed representation of a Package URL (pURL).
///
/// pURL format: `pkg:type/[namespace/]name[@version][?qualifiers][#subpath]`
///
/// Examples:
/// - `pkg:maven/com.example/my-artifact@1.2.3`  → type=maven, namespace=com.example, name=my-artifact
/// - `pkg:cargo/my-crate@0.5.0`                 → type=cargo, namespace=None, name=my-crate
#[derive(Debug)]
struct ParsedPurl {
    pkg_type: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

/// Parses a pURL string using a single regex that handles both namespaced
/// (e.g. Maven `group/artifact`) and non-namespaced (e.g. Cargo `package`) formats.
///
/// Regex breakdown:
///   `^pkg:([^/]+)/`          – mandatory "pkg:" prefix + type + first slash
///   `(?:([^/]+)/)?`          – optional namespace segment (present only when a second `/` exists before `@`)
///   `([^@?#]+)`              – package name (everything up to `@`, `?`, `#`, or end)
///   `(?:@([^?#]+))?`         – optional version after `@`
fn parse_purl(purl: &str) -> Option<ParsedPurl> {
    static PURL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^pkg:([^/]+)/(?:([^/]+)/)?([^@?#]+)(?:@([^?#]+))?").unwrap()
    });

    let caps = PURL_RE.captures(purl)?;
    Some(ParsedPurl {
        pkg_type: caps[1].to_string(),
        namespace: caps.get(2).map(|m| m.as_str().to_string()),
        name: caps[3].to_string(),
        version: caps.get(4).map(|m| m.as_str().to_string()),
    })
}

