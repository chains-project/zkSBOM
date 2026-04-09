use crate::config::Config;
use crate::database::db_dependency::get_dependencies;
use crate::map_dependencies_vulnerabilities::get_vulnerable_packages_for_cve;
use crate::method::merkle_patricia_trie::generate_formatted_proof as mpt_generate;
use crate::method::merkle_tree::generate_formatted_proof as mt_generate;
use crate::method::ozks::core::generate_formatted_proof as ozks_generate;
use crate::method::sparse_merkle_tree::generate_formatted_proof as smt_generate;
use log::{debug, error, info};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn execute_proof_flow(method: &str, commitment: &str, check: &str, config: &Config) -> String {
    let dependency_entry = get_dependencies(commitment.to_string(), method, config);
    let mut dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();

    if method.to_lowercase() != "ozks" {
        dependencies.push(dependency_entry.metadata.as_str());
    }

    let deps_to_proof: Vec<String>;

    if check.to_lowercase().starts_with("cve") {
        // check is cve
        deps_to_proof = get_vulnerable_packages_for_cve(check, config);
    } else {
        // check is dependency
        if is_valid_dep(check) {
            deps_to_proof = vec![check.to_string()];
        } else {
            panic!("Wrong format for `check`: `{}`; expected CVE or package in the format of `package@version@ecosystem`", check);
        }
    }

    // Check for Inclusion
    for dep in &dependencies {
        let stripped_dep = dep.split(';').next().unwrap_or(*dep);

        let mut stripped_dep_vdb = stripped_dep.to_string();

        if dep
            .rsplit_once('@')
            .map(|(_, right)| right)
            .unwrap_or(dep)
            .to_lowercase()
            == "go"
        {
            stripped_dep_vdb = stripped_dep.replace(":", "/");
        }

        if deps_to_proof.contains(&stripped_dep_vdb.to_string()) {
            debug!(
                "Creating inclusion proof for dep_to_proof: {}",
                stripped_dep
            );
            return if config.app.conceal {
                let concealed_dep = get_concealed_dependencies(stripped_dep);
                inclusion_proof(method, commitment, dependencies, concealed_dep, config)
            } else {
                inclusion_proof(
                    method,
                    commitment,
                    dependencies,
                    stripped_dep.to_string(),
                    config,
                )
            };
        }
    }

    // If no inclusion, fallback to non-inclusion
    if method == "merkle-tree" {
        error!("Merkle Tree doesn't support non-inclusion proofs.");
        return "".to_string();
    }

    debug!(
        "Creating non inclusion proof for deps_to_proof: {}",
        deps_to_proof.join(", ")
    );
    non_inclusion_proof(method, commitment, dependencies, deps_to_proof, config)
}

fn is_valid_dep(s: &str) -> bool {
    let parts: Vec<&str> = s.split('@').collect();
    // Ensures 3 parts exist and none of them are empty strings
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

fn inclusion_proof(
    method: &str,
    commitment: &str,
    dependencies: Vec<&str>,
    target_dep: String,
    config: &Config,
) -> String {
    let (proof_payload, elapsed) =
        call_crypto_method(method, commitment, dependencies, &target_dep, config);
    write_to_file(proof_payload, false, config);
    elapsed
}

fn non_inclusion_proof(
    method: &str,
    commitment: &str,
    dependencies: Vec<&str>,
    deps_to_proof: Vec<String>,
    config: &Config,
) -> String {
    let dep_list = if deps_to_proof.len() == 1 && deps_to_proof[0].to_lowercase().starts_with("cve")
    {
        error!("deps_to_proof[0].as_str(): {:?}", deps_to_proof[0].as_str());
        get_vulnerable_packages_for_cve(deps_to_proof[0].as_str(), config)
    } else {
        deps_to_proof.clone()
    };

    // Clear the output file before appending non-inclusion proofs
    let output_path = &config.app.output;
    let _ = File::create(output_path);

    let mut total_elapsed = "".to_string();

    for dep in dep_list {
        info!(
            "Dependency: {} is vulnerable/in the SBOM: {:?}",
            dep, deps_to_proof
        );
        let (proof_payload, elapsed) =
            call_crypto_method(method, commitment, dependencies.clone(), &dep, config);

        write_to_file(proof_payload, true, config);
        total_elapsed = elapsed;
    }

    println!("Proof written to: {}", output_path);
    total_elapsed
}

fn call_crypto_method(
    method: &str,
    commitment: &str,
    dependencies: Vec<&str>,
    target_dep: &str,
    config: &Config,
) -> (String, String) {
    match method {
        "merkle-tree" => mt_generate(commitment, dependencies, target_dep),
        "sparse-merkle-tree" => smt_generate(commitment, dependencies, target_dep),
        "merkle-patricia-trie" => mpt_generate(commitment, dependencies, target_dep),
        "ozks" => ozks_generate(commitment, dependencies, target_dep, config),
        _ => panic!("Unknown method: {}", method),
    }
}

fn write_to_file(payload: String, is_append: bool, config: &Config) {
    let output_path = &config.app.output;
    if let Some(parent) = Path::new(output_path).parent() {
        let _ = create_dir_all(parent);
    }

    let mut file = if is_append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)
            .unwrap()
    } else {
        File::create(output_path).unwrap()
    };

    let _ = writeln!(file, "{}", payload);
    if is_append {
        let _ = writeln!(file, "---");
    } else {
        println!("Proof written to: {}", output_path);
    }
}

pub fn get_concealed_dependencies(dependency: &str) -> String {
    // Normal for npm
    let dependency_str = if dependency.starts_with('@') {
        // If it starts with @, we ignore that first char for the "contains" check
        if dependency[1..].contains('@') {
            let parts: Vec<&str> = dependency.split('@').collect();
            // Since it starts with @, parts[0] will be empty, parts[1] is the name
            // We want the name (parts[1]) and the version (parts.last)
            format!("@{}@{}", parts[1], parts.last().unwrap())
        } else {
            error!("Problem parsing dependency: {}", dependency);
            dependency.to_string()
        }
    } else if dependency.contains('@') {
        // Standard case: no leading @
        let parts: Vec<&str> = dependency.split('@').collect();
        if parts.len() >= 2 {
            format!("{}@{}", parts.first().unwrap(), parts.last().unwrap())
        } else {
            error!("Problem parsing dependency: {}", dependency);
            dependency.to_string()
        }
    } else {
        error!("Problem parsing dependency: {}", dependency);
        dependency.to_string()
    };
    dependency_str
}
