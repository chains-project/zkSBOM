use crate::config::Config;
use log::debug;
use serde_json::Value;
use std::io::{BufRead, BufReader};
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
                    for version in get_all_versions(range) {
                        result.push(format!("{name}@{version}@{ecosystem}"));
                    }
                    get_all_versions(name, ecosystem, range);
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

// This ain't ideal, but should be sufficient for a prototype.
fn get_all_versions(vuln_range: &str) -> Vec<String> {
    let range: Range = vuln_range.parse().expect("Invalid range format");
    let mut versions = Vec::new();

    // 1. Extract all version points mentioned in the string
    let re = Regex::new(r"(\d+)\.(\d+)\.(\d+)").unwrap();
    let captures: Vec<_> = re.captures_iter(vuln_range).collect();

    if captures.is_empty() {
        panic!("No base version found");
    }

    // 2. Branch based on how many versions are in the range string
    if captures.len() == 1 {
        // --- SINGLE BOUND LOGIC (<, <=, >, >=) ---
        // Uses the +/- 10 window around the single target version
        let start_maj: u64 = captures[0][1].parse().unwrap();
        let start_min: u64 = captures[0][2].parse().unwrap();
        let start_pat: u64 = captures[0][3].parse().unwrap();

        let maj_start = start_maj.saturating_sub(10);
        let maj_end = start_maj + 10;

        for current_maj in maj_start..=maj_end {
            let min_start = if current_maj == start_maj {
                start_min.saturating_sub(10)
            } else {
                0
            };
            let min_end = if current_maj == start_maj {
                start_min + 10
            } else {
                10
            };

            for current_min in min_start..=min_end {
                let pat_start = if current_maj == start_maj && current_min == start_min {
                    start_pat.saturating_sub(10)
                } else {
                    0
                };
                let pat_end = if current_maj == start_maj && current_min == start_min {
                    start_pat + 10
                } else {
                    10
                };

                for current_pat in pat_start..=pat_end {
                    let v = Version {
                        major: current_maj,
                        minor: current_min,
                        patch: current_pat,
                        build: vec![],
                        pre_release: vec![],
                    };

                    if range.satisfies(&v) {
                        let v_str = v.to_string();
                        if versions.last() != Some(&v_str) {
                            versions.push(v_str);
                        }
                    }
                }
            }
        }
    } else {
        // --- DOUBLE BOUND LOGIC (>= 0.10.0, < 0.10.5) ---
        let start_maj: u64 = captures[0][1].parse().unwrap();
        let start_min: u64 = captures[0][2].parse().unwrap();
        let start_pat: u64 = captures[0][3].parse().unwrap();

        for maj_off in 0..11 {
            let current_maj = start_maj + maj_off;

            for min_off in 0..11 {
                let current_min = if maj_off == 0 {
                    start_min + min_off
                } else {
                    min_off
                };

                for pat_off in 0..11 {
                    let current_pat = if maj_off == 0 && min_off == 0 {
                        start_pat + pat_off
                    } else {
                        pat_off
                    };

                    let v = Version {
                        major: current_maj,
                        minor: current_min,
                        patch: current_pat,
                        build: vec![],
                        pre_release: vec![],
                    };

                    if range.satisfies(&v) {
                        let v_str = v.to_string();
                        if versions.last() != Some(&v_str) {
                            versions.push(v_str);
                        }
                    }
                }
            }
        }
    }

    versions
}

fn get_all_versions(name: &str, ecosystem: &str, version_range: &str) -> Vec<String> {
    debug!("Getting all vulnerable packages");
    debug!(
        "name: {}, version_range: {}, ecosystem: {}",
        name, version_range, ecosystem
    );

    match ecosystem.to_lowercase().as_str() {
        "go" => get_versions_go(name, version_range),
        "maven" => get_versions_maven(name, version_range),
        "npm" => get_versions_npm(name, version_range),
        "rust" => get_versions_rust(name, version_range),
        _ => panic!("Unsupported ecosystem: `{}`.", ecosystem),
    }
}

fn get_versions_go(name: &str, version_range: &str) -> Vec<String> {
    let url = format!("https://proxy.golang.org/{}/@v/list", name);
    let text = reqwest::blocking::get(url).unwrap().text().unwrap();
    let versions: Vec<String> = text.lines().map(String::from).collect();
    debug!("versions: {:?}", versions);

    versions
}

fn get_versions_maven(name: &str, version_range: &str) -> Vec<String> {
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

fn get_versions_npm(name: &str, version_range: &str) -> Vec<String> {
    // https://registry.npmjs.org/react
    panic!("Not yet implemented.");
}

fn get_versions_rust(name: &str, version_range: &str) -> Vec<String> {
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
