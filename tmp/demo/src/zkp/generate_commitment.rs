use core::panic;

use log::debug;
use sp_core::H256;

use crate::db::db_sbom::{Sbom, init_sbom_db, get_specific_sbom};
use crate::db::db_commitment::{Commitment, init_commitment_db, insert_commitment};

use serde_json::Value;
use rusqlite::Result;

use crate::merkle::merkle::{get_root, generate_merkle_proof, verify_merkle_proof};

pub fn generate_commitment(sbom_path: &str, vendor: &str, product: &str,version: &str) {
    debug!("Generating commitment...");
    debug!("SBOM Path: {}", sbom_path);
    debug!("Vendor: {}", vendor);
    debug!("Product: {}", product);
    debug!("Version: {}", version);

    let sbom = get_sbom(vendor, product, version);
    debug!("SBOM: {:?}", sbom);

    let vulnerabilities = extract_vulnerabilities(&sbom);
    debug!("Vulnerabilities: {:?}", vulnerabilities);

    // Generate the commitment using the vulnerabilities
    let commitment = get_root(vulnerabilities);
    
    

    // Add the commitment to the database
    let e = add_commitment_to_db(vendor, product,version, &commitment);
    if e.is_err() {
        panic!("Failed to add commitment to database: {}", e.err().unwrap());
    }
}

fn get_sbom(vendor: &str, product: &str,version: &str) -> Sbom {
    let sbom_conn = init_sbom_db().unwrap();

    let sbom: Sbom = match get_specific_sbom(&sbom_conn, vendor, product, version) {
        Ok(res) => {
            debug!("Retrieved SBOM: {:?}", res);
            res
        }
        Err(e) => {
            panic!("Failed to get sbom: {}", e);
        }
    };

    return sbom;
}

fn extract_vulnerabilities(sbom: &Sbom) -> Vec<String> {
    let json_str = &sbom.sbom;
    debug!("SBOM: {:?}", json_str);

    // Parse the string into a JSON Value
    let parsed_json: Value = serde_json::from_str(json_str).expect("Failed to parse JSON");

    // Extract the vulnerabilities array
    if let Some(cves) = parsed_json["lib"]["vulnerabilities"].as_array() {
        let cve_list: Vec<String> = cves.iter()
            .filter_map(|cve| cve.as_str().map(|s| s.to_string()))
            .collect();

        return cve_list;
    } else {
        panic!("Not implemented");
    }
}


fn add_commitment_to_db(vendor: &str, product: &str,version: &str, commitment: &H256) -> Result<()> {
    let commitment_conn = init_commitment_db().unwrap();

    let commitment = Commitment {
        vendor: vendor.to_string(),
        product: product.to_string(),
        version: version.to_string(),
        commitment: commitment.to_string(),
    };

    return insert_commitment(&commitment_conn, &commitment);
}