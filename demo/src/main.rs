use log::{info, error};
use serde_json::from_str;
use binary_merkle_tree::MerkleProof;
use sp_core::H256;

mod cli {
    pub mod cli;
}

use cli::cli::build_cli;

mod db {
    pub mod db_commitment;
    pub mod db_sbom;
}

use db::{
    db_commitment::{init_commitment_db, init_commitment_database},
    db_sbom::{init_sbom_db, init_sbom_database},
};

mod commands {
    pub mod get_commitment;
    pub mod get_zk_proof;
    pub mod upload;
    pub mod verify;
}

use commands::{
    get_commitment::get_commitment,
    get_zk_proof::get_zk_proof,
    upload::upload_sbom,
    verify::verify,
};

mod config {
    pub mod config;
}

mod zkp {
    pub mod generate_commitment;
    pub mod generate_proof;
    pub mod verify_proof;
}


mod merkle {
    pub mod merkle;
}


// fn main() {
//     println!("Hello, world!");
//     merkle();
// }

fn main() {
    // Initialize the logger
    env_logger::init();
    info!("Starting the application...");

    // Clear databases
    // clear_databases().unwrap();

    // Initialize databases
    init_sbom_database().unwrap();
    init_commitment_database().unwrap();

    // Build the CLI parser
    let matches = build_cli().get_matches();

    // Match the subcommand and call the corresponding function
    match matches.subcommand() {
        Some(("upload", sub_matches)) => {
            let sbom_path = sub_matches.get_one::<String>("sbom").unwrap();
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            upload_sbom(sbom_path, vendor, product, version);
        }
        Some(("get-commitment", sub_matches)) => {
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            get_commitment(vendor, product, version);
        }
        Some(("get-zk-proof", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let vulnerability = sub_matches.get_one::<String>("vulnerability").unwrap();
            get_zk_proof(api_key, commitment, vulnerability);
        }
        Some(("verify", sub_matches)) => {
            // let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let proof_str = sub_matches.get_one::<String>("zkproof").unwrap();
            // Convert the proof_str to MerkleProof<H256, H256>
            let proof: MerkleProof<H256, H256> = from_str(proof_str).unwrap();
            verify(proof);
        }
        _ => {
            error!("No valid subcommand provided. Use --help for usage information.");
        }
    }
}

// TODO: Remove this function
fn clear_databases() -> Result<(), Box<dyn std::error::Error>> {
    let sbom_conn = init_sbom_db()?;
    let commitment_conn = init_commitment_db()?;

    sbom_conn.execute("DELETE FROM sbom", [])?;
    commitment_conn.execute("DELETE FROM commitment", [])?;

    Ok(())
}
