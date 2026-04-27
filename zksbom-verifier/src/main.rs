use log::{debug, error, LevelFilter};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::str::FromStr;
use zksbom_verifier::cli::build_cli;
use zksbom_verifier::config::load_config;
use zksbom_verifier::method::method_handler::{
    verify, verify_merkle_patricia_trie_detailed, verify_ozks_detailed,
    verify_sparse_merkle_tree_detailed,
};
use zksbom_verifier::method::ozks::VerificationResult;

fn main() {
    let config = load_config().unwrap();
    init_logger(&config.app);
    parse_cli(&config.app);
}

fn init_logger(app_config: &zksbom_verifier::config::AppConfig) {
    let log_level = &app_config.log_level;

    match LevelFilter::from_str(log_level) {
        Ok(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or(log_level));
            debug!("Setting log level to '{}'", log_level);
        }
        Err(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));
            error!(
                "Invalid log level '{}' in config.toml. Using default 'warn'.",
                log_level
            );
        }
    };
    debug!("Logger initialized.");
}

fn parse_cli(app_config: &zksbom_verifier::config::AppConfig) {
    debug!("Parse cli...");
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("verify", sub_matches)) => {
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let proof_path = sub_matches.get_one::<String>("proof_path").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            debug!(
                "Commitment: {}, Proof Path: {}, Method: {}",
                commitment, proof_path, method
            );

            // For OZKS and Sparse Merkle Tree, use detailed verification to handle multiple proofs
            if method == "ozks" {
                let result: VerificationResult =
                    verify_ozks_detailed(commitment, proof_path, app_config);
                let status = if result.is_valid {
                    "Proof is valid."
                } else {
                    "Proof is invalid."
                };
                println!("{}", status);

                // If multiple proofs, display details
                if result.details.len() > 1 {
                    let mut proof_type = "";
                    for (_, detail) in result.details.iter().enumerate() {
                        if detail.is_member {
                            if proof_type == "" || proof_type == "Inclusion" {
                                proof_type = "Inclusion";
                            } else {
                                panic!("Mixed up proofs...")
                            }
                        } else {
                            if proof_type == "" || proof_type == "Non-Inclusion" {
                                proof_type = "Non-Inclusion";
                            } else {
                                panic!("Mixed up proofs...")
                            }
                        }
                    }
                    println!("\n{} proof verification details:", proof_type);
                    for (idx, detail) in result.details.iter().enumerate() {
                        let member_status = if detail.is_member {
                            "Yes (member)"
                        } else {
                            "No (not in trie)"
                        };
                        println!("  [{}] Dependency: {}", idx + 1, detail.dependency);
                        println!("      In trie: {}", member_status);
                    }
                } else if result.details.len() == 1 {
                    let detail = &result.details[0];
                    println!("Dependency: {}", detail.dependency);
                    let member_status = if detail.is_member {
                        "Yes (member)"
                    } else {
                        "No (not in trie)"
                    };
                    println!("  In trie: {}", member_status);
                }
            } else if method == "sparse-merkle-tree" {
                let result = verify_sparse_merkle_tree_detailed(commitment, proof_path, app_config);
                let status = if result.is_valid {
                    "Proof is valid."
                } else {
                    "Proof is invalid."
                };
                println!("{}", status);

                // Display details for all proofs
                if result.details.len() > 1 {
                    println!("\nVerified Proofs:");
                    for (idx, detail) in result.details.iter().enumerate() {
                        let proof_status = if detail.is_proof_valid {
                            "Valid"
                        } else {
                            "Invalid"
                        };
                        let proof_type = if result.is_non_inclusion {
                            "Non-Inclusion"
                        } else {
                            "Inclusion"
                        };
                        println!(
                            "  [{}] {} {}. Leaf: {}",
                            idx + 1,
                            proof_status,
                            proof_type,
                            detail.leaf
                        );
                    }
                } else if result.details.len() == 1 {
                    let detail = &result.details[0];
                    let proof_status = if detail.is_proof_valid {
                        "Valid"
                    } else {
                        "Invalid"
                    };
                    let proof_type = if result.is_non_inclusion {
                        "Non-Inclusion"
                    } else {
                        "Inclusion"
                    };
                    println!("  {} {}. Leaf: {}", proof_status, proof_type, detail.leaf);
                }
            } else if method == "merkle-patricia-trie" {
                let result =
                    verify_merkle_patricia_trie_detailed(commitment, proof_path, app_config);
                let status = if result.is_valid {
                    "Proof is valid."
                } else {
                    "Proof is invalid."
                };
                println!("{}", status);

                // Display details for all proofs
                if result.details.len() > 1 {
                    println!("\nVerified Proofs:");
                    for (idx, detail) in result.details.iter().enumerate() {
                        let proof_status = if detail.is_proof_valid {
                            "Valid"
                        } else {
                            "Invalid"
                        };
                        let proof_type = if result.is_non_inclusion {
                            "Non-Inclusion"
                        } else {
                            "Inclusion"
                        };
                        println!(
                            "  [{}] {} {}. Leaf: {}",
                            idx + 1,
                            proof_type,
                            proof_status,
                            detail.leaf
                        );
                    }
                } else if result.details.len() == 1 {
                    let detail = &result.details[0];
                    let proof_status = if detail.is_proof_valid {
                        "Valid"
                    } else {
                        "Invalid"
                    };
                    println!("  {} Verified Leaf: {}", proof_status, detail.leaf);
                }
            } else {
                let is_valid = verify(commitment, proof_path, &method, app_config);
                let status = if is_valid {
                    "Proof is valid."
                } else {
                    "Proof is invalid"
                };

                // Extract dependency/key from proof file for display
                let key_info = extract_proof_key_info(proof_path);
                println!("{}", status);
                if let Some(key) = key_info {
                    println!("  Verified {}", key);
                }
            }
        }
        _ => error!("No subcommand matched"),
    }
}

fn extract_proof_key_info(proof_path: &str) -> Option<String> {
    let path = Path::new(proof_path);
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let reader = io::BufReader::new(file);

    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            let trimmed = line.trim();

            // Look for Dependency field (used in most methods)
            if let Some(value) = trimmed.strip_prefix("Dependency:") {
                return Some(value.trim().to_string());
            }

            // Look for Key field (used in some methods like sparse merkle tree)
            if let Some(value) = trimmed.strip_prefix("Key:") {
                return Some(value.trim().to_string());
            }

            // Look for Leaf field (used in merkle tree variants)
            if let Some(value) = trimmed.strip_prefix("Leaf:") {
                return Some(format!("Leaf: {}", value.trim()));
            }
        }
    }

    None
}
