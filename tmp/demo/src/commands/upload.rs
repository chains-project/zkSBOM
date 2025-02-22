use log::{error, info, debug};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::db::db_sbom::{
    insert_sbom,
    Sbom,
    get_sbom_db_connection
};

use crate::zkp::generate_commitment::generate_commitment;

// Function for the "upload" command
pub fn upload_sbom(sbom_path: &str, vendor: &str, product: &str,version: &str) { //upload_sbom(sbom_path, vendor, product, version)
    info!("Uploading/updating SBOM from: {sbom_path}");
    
    // Check the file extension
    if let Some(extension) = Path::new(sbom_path).extension() {
        match extension.to_str().unwrap() {
            "json" => {
                if let Ok(contents) = read_file(sbom_path) {
                        debug!("JSON file content:\n{}", contents);
                        info!("JSON file content read successfully.");
                        // You can now parse the JSON content using a crate like `serde_json`

                        // Inserting the SBOM into the database
                        let sbom = Sbom {
                            sbom: contents.to_string(),
                            vendor: vendor.to_string(),
                            product: product.to_string(),
                            version: version.to_string(),
                        };

                        debug!("Inserting SBOM into the database: {:?}", sbom);

                        let sbom_db_conn = get_sbom_db_connection();
                        let res = insert_sbom(&sbom_db_conn, &sbom);
                        if res.is_err() {
                            error!("Failed to insert SBOM into the database: {}", res.err().unwrap());
                        }
                }

                // Create Commitment
                generate_commitment(sbom_path, vendor, product,version);
            }
            "xml" => {
                if let Ok(contents) = read_file(sbom_path) {
                    debug!("XML file content:\n{}", contents);
                    info!("XML file content read successfully.");
                }
            }
            _ => {
                error!("Unsupported file type: {:?}", extension);
            }
        }
    } else {
        error!("File has no extension.");
    }
}

fn read_file(sbom_path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(sbom_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}
