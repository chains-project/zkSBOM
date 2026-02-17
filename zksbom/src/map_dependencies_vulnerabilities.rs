use crate::config::Config;
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

pub fn map_dependencies_vulnerabilities(config: &Config) -> bool {
    // Collect all dependencies in a list
    let dependencies = get_all_dependencies(config).unwrap();
    debug!("Dependencies: {:?}", dependencies);

    // Call
    let dependencies_refs: Vec<&str> = dependencies.iter().map(|s| s.as_str()).collect();
    let mapping = mapping(dependencies_refs, config);

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
        _ = insert_vulnerabilities(db_entry, config);
    }

    println!("Mapping dependencies and vulnerabilities completed.");
    true
}

pub fn get_mapping_for_dependencies(
    dependencies: Vec<&str>,
    config: &Config,
) -> HashMap<String, Vec<String>> {
    let mut result: HashMap<String, Vec<String>> = HashMap::new();

    for dependency in dependencies {
        let dependency = dependency
            .rfind(';')
            .map_or(dependency, |idx| &dependency[..idx]);

        match get_vulnerabilities(dependency, config) {
            Ok(Some(vulnerabilities)) => {
                result.insert(dependency.to_string(), vulnerabilities);
            }
            Ok(None) => {
                debug!("No vulnerabilities found for dependency: {}", dependency);
            }
            Err(e) => {
                debug!("Failed to get vulnerabilities for {}: {:?}", dependency, e);
            }
        }
    }

    debug!("Result: {:?}", result);
    return result;
}

// Function to map dependencies and its vulnerabilities
fn mapping(dependencies: Vec<&str>, config: &Config) -> HashMap<String, Vec<String>> {
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

        let vulnerabilities = check_vulnerabilities(name, version, ecosystem, config);

        dependency_vulnerabilities_map.insert(dependency.to_string(), vulnerabilities);
    }

    return dependency_vulnerabilities_map;
}

fn check_vulnerabilities(
    name: &str,
    version: &str,
    ecosystem: &str,
    config: &Config,
) -> Vec<String> {
    // Construct GraphQL query
    let query = format!(
        r#"{{"query": "{{ securityVulnerabilities(first: 5, ecosystem: {}, package: \"{}\") {{ nodes {{ package {{ name ecosystem }} vulnerableVersionRange firstPatchedVersion {{ identifier }} advisory {{ ghsaId summary severity permalink }} }} }} }}"}}"#,
        ecosystem, name
    );

    // Debugging: Print the actual query to check for correctness
    debug!("Query: {}", query);

    // Load GitHub token from the config
    let token = &config.app.github_token;

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
            if let (
                Some(vulnerable_version_range),
                Some(ghsa_id),
                Some(first_patched_version),
                Some(severity),
                Some(permalink),
            ) = (
                vulnerability
                    .get("vulnerableVersionRange")
                    .and_then(|v| v.as_str()),
                vulnerability
                    .get("advisory")
                    .and_then(|a| a.get("ghsaId"))
                    .and_then(|v| v.as_str()),
                vulnerability
                    .get("firstPatchedVersion")
                    .and_then(|f| f.get("identifier"))
                    .and_then(|v| v.as_str()),
                vulnerability
                    .get("advisory")
                    .and_then(|a| a.get("severity"))
                    .and_then(|v| v.as_str()),
                vulnerability
                    .get("advisory")
                    .and_then(|a| a.get("permalink"))
                    .and_then(|v| v.as_str()),
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
                debug!(
                    "Skipping vulnerability due to missing required fields: {:?}",
                    vulnerability
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
        debug!("CVE ID not found for GHSA ID: {}", ghsa_id);
        return String::new();
    }
}

pub fn get_dependencies_for_vulnerability(cve: &str, limit: usize) -> Vec<String> {
    debug!("Querying GitHub for packages vulnerable to CVE: {}", cve);

    let mut vulnerable_packages = Vec::new();

    // Search GitHub's advisory database for this CVE
    // Use the search endpoint to find advisories with this CVE
    let search_url = format!("https://api.github.com/advisories?query=cve:{}", cve);

    let client = reqwest::blocking::Client::new();

    let response = match client
        .get(&search_url)
        .header("User-Agent", "rust-reqwest")
        .header("Accept", "application/vnd.github+json")
        .send()
    {
        Ok(resp) => resp,
        Err(e) => {
            error!("Request to GitHub advisories failed for CVE {}: {}", cve, e);
            return Vec::new();
        }
    };

    let response = match response.error_for_status() {
        Ok(resp) => resp,
        Err(e) => {
            error!("HTTP error querying GitHub advisories for {}: {}", cve, e);
            return Vec::new();
        }
    };

    let json: Value = match response.json() {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to parse GitHub advisories JSON for {}: {}", cve, e);
            return Vec::new();
        }
    };

    // Parse the response to extract packages
    // GitHub API returns an array of advisories
    if let Some(advisories) = json.as_array() {
        for advisory in advisories.iter().take(limit) {
            // Extract package information from advisory
            if let Some(affected_packages) =
                advisory.get("affected_packages").and_then(|p| p.as_array())
            {
                for package_obj in affected_packages {
                    if let (Some(package_name), Some(ecosystem)) = (
                        package_obj
                            .get("package")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str()),
                        package_obj
                            .get("package")
                            .and_then(|p| p.get("ecosystem"))
                            .and_then(|e| e.as_str()),
                    ) {
                        // Get version if available, otherwise use "latest"
                        let version = package_obj
                            .get("vulnerable_version_range")
                            .and_then(|v| v.as_str())
                            .unwrap_or("latest");

                        // Format as name@version@ecosystem
                        let formatted = format!("{}@{}@{}", package_name, version, ecosystem);
                        debug!("Found vulnerable package: {}", formatted);
                        vulnerable_packages.push(formatted);

                        if vulnerable_packages.len() >= limit {
                            break;
                        }
                    }
                }
                if vulnerable_packages.len() >= limit {
                    break;
                }
            }
        }
    }

    if vulnerable_packages.is_empty() {
        warn!("No packages found in GitHub advisories for CVE: {}", cve);
    }

    vulnerable_packages
}

pub fn get_vulnerable_packages_for_cve(cve_id: &str, config: &Config) -> Vec<String> {
    debug!("Getting vulnerable packages for CVE: {}", cve_id);
    // Prepare the GraphQL query as a Rust raw string WITHOUT extra backslashes!
    let graphql_query = format!(
        r#"
        query {{
            securityAdvisories(
                first: 5,
                identifier: {{type: CVE, value: "{}"}}
            ) {{
                nodes {{
                    vulnerabilities(first: 100) {{
                        nodes {{
                            package {{ name ecosystem }}
                            vulnerableVersionRange
                        }}
                    }}
                }}
            }}
        }}
        "#,
        cve_id
    );

    // Now wrap in JSON correctly:
    let query_json = serde_json::json!({ "query": graphql_query }).to_string();

    let token = &config.app.github_token;

    let output = Command::new("curl")
        .arg("-H")
        .arg(format!("Authorization: Bearer {}", token))
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(query_json)
        .arg("https://api.github.com/graphql")
        .output()
        .expect("Failed to execute curl");

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("Raw curl output: {}", stdout);

    let value: Value = serde_json::from_str(&stdout).expect("Invalid JSON in response");

    let mut result = Vec::new();

    if let Some(nodes) = value
        .get("data")
        .and_then(|d| d.get("securityAdvisories"))
        .and_then(|sa| sa.get("nodes"))
        .and_then(|n| n.as_array())
    {
        for advisory in nodes {
            if let Some(vulns) = advisory
                .get("vulnerabilities")
                .and_then(|v| v.get("nodes"))
                .and_then(|vn| vn.as_array())
            {
                for vuln in vulns {
                    let name = vuln
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("");
                    let ecosystem = vuln
                        .get("package")
                        .and_then(|p| p.get("ecosystem"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("");
                    let range = vuln
                        .get("vulnerableVersionRange")
                        .and_then(|r| r.as_str())
                        .unwrap_or("");
                    if let Some(min_ver) = extract_lower_version(range) {
                        result.push(format!("{name}@{min_ver}@{ecosystem}"));
                    }
                }
            }
        }
    }
    result
}

fn extract_lower_version(vuln_range: &str) -> Option<&str> {
    // Find a substring like ">= " and grab what's after.
    for part in vuln_range.split(',') {
        let part = part.trim();
        if let Some(idx) = part.find(">=") {
            // Get text after '>=' and trim
            let ver = part[idx + 2..].trim();
            return Some(ver);
        }
        // Some advisories might use ">" only
        if let Some(idx) = part.find('>') {
            let ver = part[idx + 1..].trim();
            return Some(ver);
        }
    }
    None
}
