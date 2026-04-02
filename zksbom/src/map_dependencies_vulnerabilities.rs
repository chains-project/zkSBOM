use crate::config::Config;
use log::{debug, error};
use roxmltree::Document;
use semver::Version;
use serde_json::Value;
use std::process::Command;
use std::str;

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
                    let all_versions = get_all_versions(name, ecosystem);
                    let vulnerable_versions = get_vulnerable_versions(all_versions, range);
                    for vulnerable_version in vulnerable_versions {
                        result.push(format!("{name}@{vulnerable_version}@{ecosystem}"));
                    }
                }
            }
        }
    }

    debug!(
        "Found vulnerable packages for {}: {}",
        cve_id,
        result.join(", ")
    );
    result
}

pub fn get_all_versions(name: &str, ecosystem: &str) -> Vec<String> {
    debug!("Getting all vulnerable packages");
    debug!("name: {}, ecosystem: {}", name, ecosystem);

    match ecosystem.to_lowercase().as_str() {
        "go" => get_versions_go(name),
        "maven" => get_versions_maven(name),
        "npm" => get_versions_npm(name),
        "rust" => get_versions_rust(name),
        _ => panic!("Unsupported ecosystem: `{}`.", ecosystem),
    }
}

fn get_versions_go(name: &str) -> Vec<String> {
    let url = format!("https://proxy.golang.org/{}/@v/list", name);
    let text = reqwest::blocking::get(url).unwrap().text().unwrap();
    let versions: Vec<String> = text.lines().map(String::from).collect();
    debug!("versions: {:?}", versions);

    versions
}

fn get_versions_maven(name: &str) -> Vec<String> {
    let url = format!(
        "https://repo1.maven.org/maven2/{}/maven-metadata.xml",
        name.replace(".", "/").replace(":", "/")
    );
    debug!("url: {}", url);

    let xml_data = reqwest::blocking::get(url).unwrap().text().unwrap();

    let doc = match Document::parse(&xml_data) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let versions: Vec<String> = doc
        .descendants()
        .filter(|n| n.has_tag_name("version"))
        .filter_map(|n| n.text())
        .map(String::from)
        .collect();

    versions
}

fn get_versions_npm(name: &str) -> Vec<String> {
    let url = format!("https://registry.npmjs.org/{}", name);
    let text = reqwest::blocking::get(url).unwrap().text().unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();

    // Initialize an empty vector to hold the results
    let mut versions = Vec::new();

    // Access the "versions" object and collect the keys
    if let Some(versions_map) = v.get("versions").and_then(|v| v.as_object()) {
        versions = versions_map.keys().map(|k| k.to_string()).collect();
    }

    debug!("versions: {:?}", versions);
    versions
}

fn get_versions_rust(name: &str) -> Vec<String> {
    let pairs: Vec<String> = name
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .take(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();
    let dir = pairs.join("/");

    let url = format!("https://index.crates.io/{}/{}", dir, name);
    let response = reqwest::blocking::get(url).unwrap().text().unwrap();

    // Process the response string
    let versions: Vec<String> = response
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let json: Value = serde_json::from_str(line).ok()?;
            json.get("vers")?.as_str().map(|v| v.to_string())
        })
        .collect();

    debug!("versions: {:?}", versions);

    versions
}

// Normalizes "loose" versions (e.g., "2.4" -> "2.4.0") so the semver crate can parse them.
fn loose_parse(v: &str) -> Option<Version> {
    // 1. Separate the version numbers from any pre-release/metadata tags (e.g., -alpha)
    let mut main_parts = v.splitn(2, |c| c == '-' || c == '+');
    let ver_num = main_parts.next()?;
    let metadata = v.get(ver_num.len()..); // Store the "-alpha", "+build", etc.

    // 2. Pad the version numbers with ".0" until there are 3 parts
    let mut parts: Vec<&str> = ver_num.split('.').collect();
    while parts.len() < 3 {
        parts.push("0");
    }

    let mut normalized = parts.join(".");

    // 3. Re-attach the metadata tags
    if let Some(m) = metadata {
        normalized.push_str(m);
    }

    Version::parse(&normalized).ok()
}

pub fn get_vulnerable_versions(all_versions: Vec<String>, version_range: &str) -> Vec<String> {
    // Parse the version range into a list of (operator, Version) tuples
    let conditions: Vec<(&str, Version)> = version_range
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            let (op, val) = if let Some(stripped) = part.strip_prefix(">=") {
                (">=", stripped.trim())
            } else if let Some(stripped) = part.strip_prefix("<=") {
                ("<=", stripped.trim())
            } else if let Some(stripped) = part.strip_prefix('>') {
                (">", stripped.trim())
            } else if let Some(stripped) = part.strip_prefix('<') {
                ("<", stripped.trim())
            } else if let Some(stripped) = part.strip_prefix('=') {
                ("=", stripped.trim())
            } else {
                ("=", part.trim())
            };

            // Use loose_parse to ensure "2.4" becomes a valid "2.4.0" Version object
            loose_parse(val).map(|v| (op, v))
        })
        .collect();

    // Filter the incoming versions
    all_versions
        .into_iter()
        .filter(|v_str| {
            // Also use loose_parse for the candidate versions (like "2.4")
            if let Some(version) = loose_parse(v_str) {
                // Check if the version satisfies ALL conditions
                conditions.iter().all(|(op, target_version)| match *op {
                    ">=" => version >= *target_version,
                    "<=" => version <= *target_version,
                    ">" => version > *target_version,
                    "<" => version < *target_version,
                    "=" => version == *target_version,
                    _ => false,
                })
            } else {
                false // Ignore versions that cannot be parsed at all
            }
        })
        .collect()
}
