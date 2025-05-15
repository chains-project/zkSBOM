use crate::config::load_config;
use log::{debug, error, warn};
use reqwest;
use semver::Version;
use semver::VersionReq;
use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;
use std::str;

use crate::database::db_dependency::get_all_dependencies;
use crate::database::db_vulnerabilities::{
    get_vulnerabilities, insert_vulnerabilities, VulnerabilityDbEntry,
};

pub fn map_dependencies_vulnerabilities() -> bool {
    // Collect all dependencies in a list
    let dependencies = get_all_dependencies().unwrap();
    debug!("Dependencies: {:?}", dependencies);

    // Call
    let dependencies_refs: Vec<&str> = dependencies.iter().map(|s| s.as_str()).collect();
    let mapping = mapping(dependencies_refs);

    // Insert the mapping into the database
    for (dependency, vulnerabilities) in mapping {
        debug!(
            "Dependency: {}, Vulnerabilities: {:?}",
            dependency, vulnerabilities
        );

        // insert in db
        let db_entry = VulnerabilityDbEntry {
            dependency: dependency.to_string(),
            vulnerabilities: vulnerabilities.join(","),
        };
        _ = insert_vulnerabilities(db_entry);
    }

    return true;
}

pub fn get_mapping_for_dependencies(dependencies: Vec<&str>) -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();

    for dependency in dependencies {
        let dependency = dependency
            .rfind(';')
            .map_or(dependency, |idx| &dependency[..idx]);

        match get_vulnerabilities(dependency) {
            Ok(Some(vulnerabilities)) => {
                result.insert(dependency.to_string(), vulnerabilities);
            }
            Ok(None) => {
                error!("No vulnerabilities found for dependency: {}", dependency);
            }
            Err(e) => {
                error!("Failed to get vulnerabilities for {}: {:?}", dependency, e);
            }
        }
    }

    debug!("Result: {:?}", result);
    return result;
}

// Function to map dependencies and its vulnerabilities
fn mapping(dependencies: Vec<&str>) -> HashMap<String, Vec<String>> {
    // Create List of dependencies with vulnerabilities
    let mut dependency_vulnerabilities_map: HashMap<String, Vec<String>> = HashMap::new();

    for dependency in dependencies {
        let parts: Vec<&str> = dependency.split("@").collect();
        let name = parts[0];
        let version = parts[1];
        let ecosystem = parts[2];

        debug!(
            "Checking for vulnerabilities in: {}@{}@{}",
            name, version, ecosystem
        );

        let vulnerabilities = check_vulnerabilities(name, version, ecosystem);

        dependency_vulnerabilities_map.insert(dependency.to_string(), vulnerabilities);
    }

    return dependency_vulnerabilities_map;
}

fn check_vulnerabilities(name: &str, version: &str, ecosystem: &str) -> Vec<String> {
    // Construct GraphQL query
    let query = format!(
        r#"{{"query": "{{ securityVulnerabilities(first: 2, ecosystem: {}, package: \"{}\") {{ nodes {{ package {{ name ecosystem }} vulnerableVersionRange firstPatchedVersion {{ identifier }} advisory {{ ghsaId summary severity permalink }} }} }} }}"}}"#,
        ecosystem, name
    );

    // Debugging: Print the actual query to check for correctness
    debug!("Query: {}", query);

    // Load GitHub token from the config
    let config = load_config().unwrap();
    let token = config.app.github_token;

    // Execute the curl request to GitHub's GraphQL API
    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
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
    debug!("Response: {}", response);

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
            // let vulnerable_version_range =
            //     vulnerability["vulnerableVersionRange"].as_str().unwrap();
            // let ghsa_id = vulnerability["advisory"]["ghsaId"].as_str().unwrap();
            // let first_patched_version = vulnerability["firstPatchedVersion"]["identifier"]
            //     .as_str()
            //     .unwrap();
            // let severity = vulnerability["advisory"]["severity"].as_str().unwrap();
            // let permalink = vulnerability["advisory"]["permalink"].as_str().unwrap();

            // debug!("GHSA ID: {}", ghsa_id);
            // debug!("Vulnerable version range: {}", vulnerable_version_range);
            // debug!("First patched version: {}", first_patched_version);
            // debug!("Severity: {}", severity);
            // debug!("Advisory: {}", permalink);

            // // Compare your version with the vulnerable version range
            // let version_req = VersionReq::parse(vulnerable_version_range).unwrap();
            // let current_version = Version::parse(version).unwrap();

            // if version_req.matches(&current_version) {
            //     debug!(
            //         "Your version {} is affected by this vulnerability!",
            //         version
            //     );

            //     // Get the CVE ID from the GHSA ID
            //     let cve = get_cve_id(ghsa_id);
            //     debug!("GHSA ID '{}' relates to CVE ID: '{}'", ghsa_id, cve);

            //     // Add vulnerability to list if not empty sting
            //     if cve != String::new() {
            //         list_vulnerabilities.push(cve);
            //     }
            if let (
                Some(vulnerable_version_range),
                Some(ghsa_id),
                Some(first_patched_version),
                Some(severity),
                Some(permalink)
            ) = (
                vulnerability.get("vulnerableVersionRange").and_then(|v| v.as_str()),
                vulnerability.get("advisory").and_then(|a| a.get("ghsaId")).and_then(|v| v.as_str()),
                vulnerability.get("firstPatchedVersion").and_then(|f| f.get("identifier")).and_then(|v| v.as_str()),
                vulnerability.get("advisory").and_then(|a| a.get("severity")).and_then(|v| v.as_str()),
                vulnerability.get("advisory").and_then(|a| a.get("permalink")).and_then(|v| v.as_str()),
            ) {
                debug!("GHSA ID: {}", ghsa_id);
                debug!("Vulnerable version range: {}", vulnerable_version_range);
                debug!("First patched version: {}", first_patched_version);
                debug!("Severity: {}", severity);
                debug!("Advisory: {}", permalink);
            
                if let (Ok(version_req), Ok(current_version)) = (
                    VersionReq::parse(vulnerable_version_range),
                    Version::parse(version),
                ) {
                    if version_req.matches(&current_version) {
                        debug!(
                            "Your version {} is affected by this vulnerability!",
                            version
                        );
            
                        let cve = get_cve_id(ghsa_id);
                        debug!("GHSA ID '{}' relates to CVE ID: '{}'", ghsa_id, cve);
            
                        if !cve.is_empty() {
                            list_vulnerabilities.push(cve);
                        }
                    }
                } else {
                    debug!(
                        "Failed to parse version or version requirement: '{}', '{}'",
                        vulnerable_version_range, version
                    );
                }
            } else {
                debug!("Skipping vulnerability due to missing required fields: {:?}", vulnerability);
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
