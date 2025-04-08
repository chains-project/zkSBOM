use crate::config::load_config;
use crate::database::db_commitment::get_commitment as get_db_commitment;
use crate::database::db_dependency::get_dependencies;
use crate::method::merkle_tree::{create_commitment as create_merkle_commitment, generate_proof};
use binary_merkle_tree::MerkleProof;
use log::{debug, error, info, warn};
use reqwest;
use semver::Version;
use semver::VersionReq;
use serde_json::Value;
use sp_core::H256;
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::str;

pub fn create_commitment(dependencies: Vec<&str>) -> (String, Vec<String>) {
    // TODO: Implement handling for different methods
    let merkle_root_leaves = create_merkle_commitment(dependencies);
    let commitment = merkle_root_leaves.root;
    let dependencies = merkle_root_leaves.leaves;

    return (commitment, dependencies);
}

pub fn get_commitment(vendor: &str, product: &str, version: &str) -> String {
    debug!(
        "Getting commitment for vendor: {}, product: {}, version: {}",
        vendor, product, version
    );
    let commitment =
        get_db_commitment(vendor.to_string(), product.to_string(), version.to_string()).commitment;
    debug!("Commitment: {}", commitment);

    return commitment;
}

pub fn get_zkp(_api_key: &str, method: &str, commitment: &str, dependency: &str) {
    match method {
        "Merkle Tree" => {
            info!("Merkle Tree");
            let proof = generate_proof(commitment.to_string(), dependency.to_string());

            print_proof(proof);
        }
        "zkp" => {
            info!("ZKP");
        }
        "test" => {
            let dep_vul_map = map_dependencies_vulnerabilities(commitment.to_string());
            for (key, values) in &dep_vul_map {
                debug!("Dependency: {}, Vulnerabilities: {:?}", key, values);
            }

            // TODO: Use different input for this; use dependency input for now as vulnerability.
            let vulnerability = dependency;

            for (key, values) in &dep_vul_map {
                if values.contains(&vulnerability.to_string()) {
                    debug!("Dependency: {} is vulnerable to: {}", key, vulnerability);

                    let proof = generate_proof(commitment.to_string(), key.to_string());

                    print_proof(proof);

                    break; // Break the loop after finding the first match
                }
            }
        }
        _ => {
            error!("Unknown method: {}", method);
        }
    }
}

pub fn get_zkp_full(
    _api_key: &str,
    method: &str,
    vendor: &str,
    product: &str,
    version: &str,
    dependency: &str,
) {
    let commitment = get_commitment(vendor, product, version);
    get_zkp(_api_key, method, &commitment, dependency);
}

fn print_proof(proof: MerkleProof<H256, H256>) {
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

    if let Err(e) = writeln!(file, "Proof: {:?}", proof.proof) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Number of Leaves: {:?}", proof.number_of_leaves) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Leaf Index: {:?}", proof.leaf_index) {
        error!("Error writing to file: {}", e);
        return;
    }
    if let Err(e) = writeln!(file, "Leaf: {:?}", proof.leaf) {
        error!("Error writing to file: {}", e);
        return;
    }

    println!("Proof written to: {}", output_path);
}

// Function to map dependencies and its vulnerabilities
pub fn map_dependencies_vulnerabilities(commitment: String) -> HashMap<String, Vec<String>> {
    // Get dependencies from the database
    let dependencies: Vec<String> = get_dependencies(commitment)
        .dependencies_clear_text
        .split(",")
        .map(|s| s.to_string())
        .collect();
    debug!("Dependencies: {:?}", dependencies);

    // Create List of dependencies with vulnerabilities
    let mut dependency_vulnerabilities_map: HashMap<String, Vec<String>> = HashMap::new();

    for dependency in dependencies {
        let parts: Vec<&str> = dependency.split("@").collect();
        let name = parts[0];
        let version = parts[1];
        let ecosystem = parts[2];
        debug!("Checking for vulnerabilities in: {}@{}@{}", name, version, ecosystem);

        let vulnerabilities = check_vulnerabilities(name, version, ecosystem);

        dependency_vulnerabilities_map.insert(dependency, vulnerabilities);
    }

    return dependency_vulnerabilities_map;
}

fn check_vulnerabilities(name: &str, version: &str, ecosystem: &str) -> Vec<String> {
    // Construct GraphQL query
    // TODO: Hardcoded ecosystem for now
    let query = format!(
        r#"{{"query": "{{ securityVulnerabilities(first: 2, ecosystem: {}, package: \"{}\") {{ nodes {{ package {{ name ecosystem }} vulnerableVersionRange firstPatchedVersion {{ identifier }} advisory {{ ghsaId summary severity permalink }} }} }} }}"}}"#,
        ecosystem, name
    );

    // Debugging: Print the actual query to check for correctness
    debug!("Query: {}", query);

    // Load GitHub token from the config
    let config = load_config().unwrap();
    let token = config.app.github_token;

    // let command_p = format!(
    //     "curl -X POST -H \"Authorization: Bearer {}\" -H \"Content-Type: application/json\" -d '{}' https://api.github.com/graphql",
    //     token, query
    // );
    // error!("Command: {}", command_p);

    // Execute the curl request to GitHub's GraphQL API
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        // .arg("-H")
        // .arg(format!("Authorization: Bearer {}", token))
        // .arg("-H")
        // .arg("Content-Type: application/json")
        // .arg("-d")
        // .arg(query)
        // .arg("https://api.github.com/graphql")
        // .output()
        // .expect("Failed to execute curl command");
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", token))
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(query)
        .arg("https://api.github.com/graphql")
        .output()
        .expect("Failed to execute curl command");

    // Check and print the response
    let response = str::from_utf8(&output.stdout).unwrap();
    error!("Response: {}", response);

    if !output.status.success() {
        error!("Error: {:?}", &output.stdout);
    }

    let mut list_vulnerabilities: Vec<String> = Vec::new();

    // Parse the response
    let response_json: serde_json::Value = serde_json::from_str(response).unwrap();
    if let Some(vulnerabilities) =
        response_json["data"]["securityVulnerabilities"]["nodes"].as_array()
    {
        for vulnerability in vulnerabilities {
            let vulnerable_version_range =
                vulnerability["vulnerableVersionRange"].as_str().unwrap();
            let ghsa_id = vulnerability["advisory"]["ghsaId"].as_str().unwrap();
            let first_patched_version = vulnerability["firstPatchedVersion"]["identifier"]
                .as_str()
                .unwrap();
            let severity = vulnerability["advisory"]["severity"].as_str().unwrap();
            let permalink = vulnerability["advisory"]["permalink"].as_str().unwrap();

            debug!("GHSA ID: {}", ghsa_id);
            debug!("Vulnerable version range: {}", vulnerable_version_range);
            debug!("First patched version: {}", first_patched_version);
            debug!("Severity: {}", severity);
            debug!("Advisory: {}", permalink);

            // Compare your version with the vulnerable version range
            let version_req = VersionReq::parse(vulnerable_version_range).unwrap();
            let current_version = Version::parse(version).unwrap();

            if version_req.matches(&current_version) {
                debug!(
                    "Your version {} is affected by this vulnerability!",
                    version
                );

                // Get the CVE ID from the GHSA ID
                let cve = get_cve_id(ghsa_id);
                debug!("GHSA ID '{}' relates to CVE ID: '{}'", ghsa_id, cve);

                // Add vulnerability to list if not empty sting
                if cve != String::new() {
                    list_vulnerabilities.push(cve);
                }
            } else {
                debug!(
                    "Your version {} is not affected by this vulnerability.",
                    version
                );
            }
        }
    }

    return list_vulnerabilities;
}

fn get_cve_id(ghsa_id: &str) -> String {
    let url = format!("https://api.github.com/advisories/{}", ghsa_id);

    let client = reqwest::blocking::Client::new();

    let response = match client.get(&url).header("User-Agent", "rust-reqwest").send() {
        Ok(resp) => resp,
        Err(e) => {
            error!("Request failed: {}", e);
            return String::new();
        }
    };

    let response = match response.error_for_status() {
        Ok(resp) => resp,
        Err(e) => {
            error!("HTTP error: {}", e);
            return String::new();
        }
    };

    let json: Value = match response.json() {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to parse JSON: {}", e);
            return String::new();
        }
    };

    if let Some(cve_id) = json.get("cve_id").and_then(|v| v.as_str()) {
        return cve_id.to_string();
    } else {
        warn!("CVE ID not found for GHSA ID: {}", ghsa_id);
        return String::new();
    }
}
