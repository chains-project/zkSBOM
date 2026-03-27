use crate::config::Config;
use log::{debug, error};
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
                    if let Some(min_ver) = extract_lower_version(range) {
                        result.push(format!("{name}@{min_ver}@{ecosystem}"));
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

// TODO: Get all vulnerable versions
fn extract_lower_version(vuln_range: &str) -> Option<&str> {
    debug!("vuln_range: {}", vuln_range);
    // vuln_range: >= 0.10.0, < 0.10.70

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
