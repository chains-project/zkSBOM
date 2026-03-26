use crate::config::Config;
use crate::database::db_dependency::get_dependencies;
use crate::map_dependencies_vulnerabilities::{
    get_mapping_for_dependencies, get_vulnerable_packages_for_cve,
};
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
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone(), config);

    // 1. Check for Inclusion
    for dep in &dependencies {
        let stripped_dep = dep.split(';').next().unwrap_or(*dep);
        if dep_vul_map.contains_key(stripped_dep) || stripped_dep == check {
            if dep_vul_map
                .get(stripped_dep)
                .map_or(false, |vulns| vulns.contains(&check.to_string()))
                || stripped_dep == check
            {
                debug!(
                    "Dependency: {} is vulnerable to/in the SBOM: {}",
                    dep, check
                );
                let concealed_dep = get_concealed_dependencies(dep);

                return inclusion_proof(method, commitment, dependencies, concealed_dep, config);
            }
        }
    }

    // 2. If no inclusion found, fallback to Non-Inclusion
    if method == "merkle-tree" {
        println!("Merkle Tree doesn't support non-inclusion proofs.");
        return "".to_string();
    }

    non_inclusion_proof(method, commitment, dependencies, check, config)
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
    check: &str,
    config: &Config,
) -> String {
    let dep_list = if check.to_lowercase().starts_with("cve") {
        get_vulnerable_packages_for_cve(check, config)
    } else {
        vec![check.to_string()]
    };

    // Clear the output file before appending non-inclusion proofs
    let output_path = &config.app.output;
    let _ = File::create(output_path);

    let mut total_elapsed = "".to_string();

    for dep in dep_list {
        info!("Dependency: {} is vulnerable/in the SBOM: {}", dep, check);
        let (proof_payload, elapsed) =
            call_crypto_method(method, commitment, dependencies.clone(), &dep, config);

        write_to_file(proof_payload, true, config);
        total_elapsed = elapsed; // Note: returns the last elapsed time or you can accumulate
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
    if dependency.contains('@') {
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
    }
}
