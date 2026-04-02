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
                    let all_versions = new_get_all_versions(name, ecosystem);
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

fn new_get_all_versions(name: &str, ecosystem: &str) -> Vec<String> {
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

    debug!("versions: {:?}", versions);
    versions
}

fn get_versions_npm(name: &str) -> Vec<String> {
    error!("name: {}", name);
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

fn get_vulnerable_versions(all_versions: Vec<String>, version_range: &str) -> Vec<String> {
    debug!("All versions: {:?}", all_versions);
    debug!("Version range: {:?}", version_range);

    // Parse the version range into a list of (operator, Version) tuples
    let conditions: Vec<(&str, Version)> = version_range
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            // Extract the operator and the version string safely
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
                ("=", part.trim()) // Implicit exact match if no operator is provided
            };

            // Only keep conditions where the target version parses successfully
            Version::parse(val).ok().map(|v| (op, v))
        })
        .collect();

    // Filter the incoming versions
    let vulnerable_versions = all_versions
        .into_iter()
        .filter(|v_str| {
            // Attempt to parse the candidate version
            if let Ok(version) = Version::parse(v_str) {
                // A version is vulnerable if it matches ALL comma-separated conditions (AND logic)
                conditions.iter().all(|(op, target_version)| match *op {
                    ">=" => version >= *target_version,
                    "<=" => version <= *target_version,
                    ">" => version > *target_version,
                    "<" => version < *target_version,
                    "=" => version == *target_version,
                    _ => false,
                })
            } else {
                // If it's not a valid semantic version, we ignore it
                false
            }
        })
        .collect();
    error!("vulnerable_versions: {:?}", vulnerable_versions);
    vulnerable_versions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_versions_go() {
        let name = "github.com/opencontainers/runc";
        let result = get_versions_go(name);

        assert_eq!(
            result,
            vec![
                "v1.0.0-rc6",
                "v1.3.0",
                "v1.0.2",
                "v1.0.0-rc8",
                "v1.2.3",
                "v1.0.0-rc90",
                "v1.0.0-rc4",
                "v1.2.6",
                "v1.1.0-rc.1",
                "v1.0.0-rc7",
                "v1.2.7",
                "v1.0.0-rc93",
                "v1.0.0",
                "v1.2.8",
                "v0.0.1",
                "v1.3.3",
                "v1.1.6",
                "v1.4.0-rc.2",
                "v1.2.5",
                "v1.1.1",
                "v1.0.0-rc95",
                "v1.3.1",
                "v1.3.4",
                "v0.0.5",
                "v1.4.1",
                "v1.0.3",
                "v1.1.3",
                "v1.2.0-rc.3",
                "v1.0.0-rc94",
                "v1.1.2",
                "v1.1.11",
                "v1.3.0-rc.1",
                "v1.0.0-rc5",
                "v1.1.12",
                "v0.0.3",
                "v1.0.0-rc10",
                "v1.0.0-rc91",
                "v0.0.4",
                "v1.0.0-rc1",
                "v1.2.4",
                "v1.3.2",
                "v1.4.0-rc.1",
                "v1.2.1",
                "v1.3.0-rc.2",
                "v1.1.5",
                "v1.0.0-rc92",
                "v0.1.0",
                "v1.4.0",
                "v0.0.2",
                "v1.1.4",
                "v1.2.0",
                "v1.2.9",
                "v0.1.1",
                "v1.1.10",
                "v1.2.2",
                "v0.0.8",
                "v0.0.9",
                "v1.1.9",
                "v1.0.0-rc9",
                "v1.1.8",
                "v1.3.5",
                "v1.5.0-rc.1",
                "v1.2.0-rc.1",
                "v1.1.13",
                "v1.1.14",
                "v1.0.0-rc3",
                "v1.0.1",
                "v1.4.0-rc.3",
                "v1.1.0",
                "v1.0.0-rc2",
                "v1.1.7",
                "v0.0.6",
                "v0.0.7",
                "v1.2.0-rc.2",
                "v1.1.15"
            ]
        );
    }

    #[test]
    fn test_get_versions_maven() {
        let name = "org.ops4j.pax.logging/pax-logging-log4j2";
        let result = get_versions_maven(name);

        assert_eq!(
            result,
            vec![
                "1.8.0", "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.9.0",
                "1.9.1", "1.9.2", "1.10.0", "1.10.1", "1.10.2", "1.10.3", "1.10.4", "1.10.5",
                "1.10.6", "1.10.7", "1.10.8", "1.10.9", "1.10.10", "1.11.0", "1.11.1", "1.11.2",
                "1.11.3", "1.11.4", "1.11.5", "1.11.6", "1.11.7", "1.11.8", "1.11.9", "1.11.10",
                "1.11.11", "1.11.12", "1.11.13", "1.11.14", "1.11.15", "1.11.16", "1.11.17",
                "1.12.0", "1.12.1", "1.12.2", "1.12.3", "1.12.4", "1.12.5", "1.12.6", "1.12.7",
                "1.12.8", "1.12.9", "1.12.10", "1.12.11", "1.12.12", "1.12.13", "1.12.14",
                "1.12.15", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6", "2.0.7",
                "2.0.8", "2.0.9", "2.0.10", "2.0.11", "2.0.12", "2.0.13", "2.0.14", "2.0.15",
                "2.0.16", "2.0.17", "2.0.18", "2.0.19", "2.1.0", "2.1.1", "2.1.2", "2.1.3",
                "2.1.4", "2.2.0", "2.2.1", "2.2.2", "2.2.3", "2.2.4", "2.2.5", "2.2.6", "2.2.7",
                "2.2.8", "2.2.9", "2.2.10", "2.2.11", "2.3.0", "2.3.1", "2.3.2"
            ]
        );
    }

    #[test]
    fn test_get_versions_npm() {
        let name = "lodash.template";
        let result = get_versions_npm(name);

        assert_eq!(
            result,
            vec![
                "2.0.0", "2.1.0", "2.2.0", "2.2.1", "2.3.0", "2.4.0", "2.4.1", "3.0.0", "3.0.1",
                "3.1.0", "3.2.0", "3.3.0", "3.3.1", "3.3.2", "3.4.0", "3.5.0", "3.5.1", "3.6.0",
                "3.6.1", "3.6.2", "4.0.0", "4.0.1", "4.0.2", "4.1.0", "4.1.1", "4.18.0", "4.18.1",
                "4.2.0", "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.3.0", "4.4.0", "4.5.0"
            ]
        );
    }

    #[test]
    fn test_get_versions_rust() {
        let name = "sparse-merkle-tree";
        let result = get_versions_rust(name);

        assert_eq!(
            result,
            vec![
                "0.1.0-alpha1",
                "0.1.0-alpha2",
                "0.1.0-alpha3",
                "0.1.0",
                "0.1.1",
                "0.1.2",
                "0.1.3",
                "0.2.0",
                "0.3.0",
                "0.3.1-pre",
                "0.4.0-rc1",
                "0.5.0-rc1",
                "0.5.0-rc2",
                "0.5.2-rc1",
                "0.5.2",
                "0.5.3",
                "0.5.4",
                "0.6.0",
                "0.6.1"
            ]
        );
    }

    #[test]
    fn test_vulnerable_range_less_than() {
        let all_versions = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "5.0.1".to_string(),
        ];
        let range = "< 5.0.1";

        let result = get_vulnerable_versions(all_versions, range);

        assert_eq!(result, vec!["1.0.0", "2.0.0"]);
    }

    #[test]
    fn test_compound_range() {
        let all_versions = vec![
            "0.9.0".to_string(),
            "0.10.2".to_string(),
            "0.10.5".to_string(),
            "0.11.0".to_string(),
        ];
        let range = ">= 0.10.0, < 0.10.5";

        let result = get_vulnerable_versions(all_versions, range);

        assert_eq!(result, vec!["0.10.2"]);
    }

    #[test]
    fn test_pre_release_versions() {
        let all_versions = vec![
            "1.0.0-beta.25".to_string(),
            "1.0.0".to_string(),
            "2.0.0".to_string(),
        ];
        let range = "< 1.0.0";

        let result = get_vulnerable_versions(all_versions, range);

        // This will include the beta version because 1.0.0-beta.25 < 1.0.0
        assert_eq!(result, vec!["1.0.0-beta.25"]);
    }
}
