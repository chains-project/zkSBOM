use log::{debug, info};

use crate::db::db_commitment::{get_specific_commitment, get_commitment_db_connection};


// Function for the "get-commitment" command
pub fn get_commitment(vendor: &str, product: &str, version: &str) -> String {
    info!("Getting commitment for product: {}, version: {}", product, version);
    
    let commitment_conn = get_commitment_db_connection();
    let commitment_entry = get_specific_commitment(&commitment_conn, vendor, product, version).unwrap();
    let commitment = commitment_entry.commitment;
    debug!("Commitment: {:?}", commitment);

    return commitment;
}
