use crate::check_dependencies_crates_io::check_dependencies;
use crate::config::Config;
use crate::database::db_commitment::{insert_commitment, CommitmentDbEntry};
use crate::database::db_dependency::{insert_dependency, DependencyDbEntry};
use crate::github_advisory_database_mapping::get_github_ecosystem_name;
use crate::method::method_handler::{create_commitments, print_timing_ns};
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use rand::distr::Alphanumeric;
use rand::Rng;
use regex::Regex;
use serde_json::{from_str, Value};
use std::time::Instant;

#[derive(Debug, Default)]
struct SbomParsed {
    vendor: String,
    product: String,
    version: String,
    dependencies: Vec<String>,
}

pub fn upload(_api_key: &str, sbom_path: &str, config: &Config) {
    let now = Instant::now();

    debug!("Uploading SBOM with path: {sbom_path}");

    // Get the SBOM file content
    let sbom_content = get_file_content(&sbom_path);

    // Parse SBOM file for dependencies, vendor, product, and version
    let parsed_sbom = parse_sbom(&sbom_content, &sbom_path, config);
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

    if config.app.conceal {
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
    }

    for leaf in &mut leaves {
        if leaf.to_lowercase().contains("npm") {
            // npm: check if it starts with "%40"
            if let Some(suffix) = leaf.strip_prefix("%40") {
                *leaf = format!("@{}", suffix);
            }
            *leaf = leaf.replace(':', "/");
        }
    }

    // Metadata leaf, only used for MT, SMT, MPT
    let metadata_leaf = format!("{};{};v{}", vendor.to_string(), &product, &version);

    // Generate Commitments
    let commitments = create_commitments(
        leaves.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
        metadata_leaf.clone(),
        config,
    );

    let (
        commitment_merkle_tree,
        commitment_sparse_merkle_tree,
        commitment_merkle_patricia_trie,
        commitment_ozks,
    ) = if config.app.only_ozks {
        (
            String::new(),
            String::new(),
            String::new(),
            commitments[0].clone(),
        )
    } else {
        (
            commitments[0].clone(),
            commitments[1].clone(),
            commitments[2].clone(),
            commitments[3].clone(),
        )
    };

    let commitment_entry = CommitmentDbEntry {
        vendor,
        product,
        version,
        commitment_merkle_tree: commitment_merkle_tree.clone(),
        commitment_sparse_merkle_tree: commitment_sparse_merkle_tree.clone(),
        commitment_merkle_patricia_trie: commitment_merkle_patricia_trie.clone(),
        commitment_ozks: commitment_ozks.clone(),
    };
    insert_commitment(commitment_entry, config);

    let dependency_entry = DependencyDbEntry {
        commitment_merkle_tree,
        commitment_sparse_merkle_tree,
        commitment_merkle_patricia_trie,
        commitment_ozks,
        dependencies: leaves.join(","),
        metadata: metadata_leaf,
    };
    insert_dependency(dependency_entry, config);

    let elapsed = now.elapsed().as_nanos().to_string();
    if config.app.timing_analysis {
        print_timing_ns(
            elapsed.as_str(),
            if config.app.only_ozks {
                "ozks"
            } else {
                "all_methods"
            },
            leaves.len().to_string().as_str(),
            config,
        );
    }
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

    sbom_string
}

fn parse_sbom(sbom_content: &str, sbom_path: &str, config: &Config) -> SbomParsed {
    let json_str = sbom_content;
    let mut sbom_parsed = SbomParsed::default();

    // Deserialize the JSON
    let json: Value = from_str(&json_str).expect("Failed to parse JSON");



    // Extract component information
    let component = json
        .get("metadata")
        .and_then(|m| m.get("component"));

    let (vendor, product, version) = if let Some(component) = component {
        // Try multiple fields for vendor: author → publisher → supplier → "unknown"
        let vendor = ["author", "publisher", "supplier"]
            .iter()
            .find_map(|&field| {
                component
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or("unknown")
            .to_string();

        // Raw name field, fall back to sbom filename stem
        let raw_name = component
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("");

        // If name contains ":", treat it as "product:version"
        let (_product, inline_version) = if raw_name.contains(':') {
            let mut parts = raw_name.splitn(2, ':');
            let p = parts.next().unwrap_or("").trim().to_string();
            let v = parts.next().unwrap_or("").trim().to_string();
            (
                if p.is_empty() { None } else { Some(p) },
                if v.is_empty() { None } else { Some(v) },
            )
        } else {
            (
                if raw_name.is_empty() { None } else { Some(raw_name.to_string()) },
                None,
            )
        };

        // Version: inline > explicit field > "unknown"
        let version = inline_version
            .or_else(|| {
                component
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Product: parsed name > sbom filename stem > "unknown"
        let product = sbom_path.to_string();

        (vendor, product, version)
    } else {
        // No metadata/component at all — use filename as product
        warn!("No metadata.component found in SBOM, falling back to filename.");
        let product = sbom_path;

        ("unknown".to_string(), product.to_string(), "unknown".to_string())
    };

    debug!("Vendor: {}, Product: {}, Version: {}", vendor, product, version);
    sbom_parsed.vendor = vendor;
    sbom_parsed.product = product;
    sbom_parsed.version = version;


    // Extract dependency information (if present)
    if let Some(components) = json["components"].as_array() {
        let mut all_dependencies = Vec::new();

        for component in components {
            debug!("Component: {:?}", component);
            let parsed_purl = parse_purl(component["purl"].as_str().unwrap_or("")).unwrap();

            let mut name = parsed_purl.name;
            if !parsed_purl.namespace.is_none() {
                name = format!("{}:{}", parsed_purl.namespace.unwrap(), name);
            }

            let ecosystem = get_github_ecosystem_name(parsed_purl.pkg_type.as_str());
            if ecosystem.is_none() {
                eprintln!("Ecosystem not found in metadata JSON");
                std::process::exit(1);
            }
            let ecosystem = ecosystem.unwrap();

            let version = parsed_purl.version.unwrap_or("unknow".to_string());
            if config.app.salt {
                debug!(
                    "Adding salt to dependency: {}@{}@{}",
                    name, version, ecosystem
                );
                let salt = create_salt();
                all_dependencies.push(format!("{}@{}@{};{}", name, version, ecosystem, salt));
            } else {
                debug!(
                    "No salt added for dependency: {}@{}@{}",
                    name, version, ecosystem
                );
                all_dependencies.push(format!("{}@{}@{}", name, version, ecosystem));
            }
        }

        debug!("All dependencies: {:?}", all_dependencies);

        if all_dependencies.is_empty() {
            warn!("No components with name and version found in the SBOM.");
        }

        all_dependencies.sort();
        all_dependencies.dedup();

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
    salt
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
    static PURL_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^pkg:([^/]+)/(?:([^/]+)/)?([^@?#]+)(?:@([^?#]+))?").unwrap());

    let caps = PURL_RE.captures(purl)?;
    Some(ParsedPurl {
        pkg_type: caps[1].to_string(),
        namespace: caps.get(2).map(|m| m.as_str().to_string()),
        name: caps[3].to_string(),
        version: caps.get(4).map(|m| m.as_str().to_string()),
    })
}
