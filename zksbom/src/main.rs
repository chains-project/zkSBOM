#[macro_use]
extern crate rocket;

use log::{debug, error, info, LevelFilter};
use std::str::FromStr;

pub mod config;
use config::load_config;

mod database {
    pub mod db_commitment;
    pub mod db_dependency;
    pub mod db_sbom;
}
use database::{
    db_commitment::{delete_db_commitment, init_db_commitment},
    db_dependency::{delete_db_dependency, init_db_dependency},
    db_sbom::{delete_db_sbom, init_db_sbom},
};
use std::env;


pub mod cli;
use cli::build_cli;

pub mod upload;
use upload::upload;

pub mod method {
    pub mod merkle_tree;
    pub mod method_handler;
}
use method::method_handler::{get_commitment as mh_get_commitment, get_zkp, get_zkp_full};

pub mod check_dependencies;
pub mod github_advisory_database_mapping;


use rocket::fs::NamedFile;
use rocket::serde::{Deserialize, json::Json};
use std::path::Path;
// use std::fs::File;
// use std::io::Write;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Request, Response};



// fn main() {
//     init_logger();
//     debug!("Logger initialized.");

//     let config = load_config().unwrap();
//     let is_clean_init = config.app.clean_init_dbs;
//     delete_dbs(is_clean_init);

//     debug!("Initializing the databases...");
//     init_dbs();

//     debug!("Parse cli...");
//     parse_cli();
// }

fn init_logger() {
    let config = load_config().unwrap();
    let log_level = config.app.log_level;

    match LevelFilter::from_str(&log_level) {
        Ok(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or(&log_level));
            info!("Setting log level to '{}'", &log_level);
        }
        Err(_) => {
            env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));
            error!(
                "Invalid log level '{}' in config.toml. Using default 'warn'.",
                &log_level
            );
        }
    };
}

fn init_dbs() {
    init_db_commitment();
    init_db_sbom();
    init_db_dependency();
}

fn delete_dbs(is_clean_init: bool) {
    if is_clean_init {
        delete_db_commitment();
        delete_db_sbom();
        delete_db_dependency();
    }
}

fn parse_cli(args: Vec<String>) -> String {
    debug!("Parse cli...");
    let matches = build_cli().get_matches_from(args);


    // let matches = build_cli()
    //     .try_get_matches_from(args)
    //     .map_err(|e| e.to_string())
    //     .unwrap();

    match matches.subcommand() {
        Some(("upload_sbom", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let sbom_path = sub_matches.get_one::<String>("sbom").unwrap();
            debug!("API Key: {}, SBOM Path: {}", api_key, sbom_path);
            let res = upload(&api_key, &sbom_path);
            println!("Upload result: {}", res);
            return res;
        }
        Some(("get_commitment", sub_matches)) => {
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            debug!(
                "Vendor: {}, Product: {}, Version: {}",
                vendor, product, version
            );
            let commitment = mh_get_commitment(&vendor, &product, &version);
            println!("Commitment: {}", commitment);
            return commitment;
        }
        Some(("get_zkp", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let commitment = sub_matches.get_one::<String>("commitment").unwrap();
            let dependency = sub_matches.get_one::<String>("dependency").unwrap();
            debug!(
                "API Key: {}, Method: {}, Commitment: {}, Dependency: {}",
                api_key, method, commitment, dependency
            );
            let filepath = get_zkp(&api_key, &method, &commitment, &dependency);
            return filepath.to_string();
        }
        Some(("get_zkp_full", sub_matches)) => {
            let api_key = sub_matches.get_one::<String>("api-key").unwrap();
            let method = sub_matches.get_one::<String>("method").unwrap();
            let vendor = sub_matches.get_one::<String>("vendor").unwrap();
            let product = sub_matches.get_one::<String>("product").unwrap();
            let version = sub_matches.get_one::<String>("version").unwrap();
            let dependency = sub_matches.get_one::<String>("dependency").unwrap();
            debug!(
                "API Key: {}, Method: {}, Vendor: {}, Product: {}, Version: {}, Dependency: {}",
                api_key, method, vendor, product, version, dependency
            );
            let filepath = get_zkp_full(&api_key, &method, &vendor, &product, &version, &dependency);
            return filepath.to_string();
        }
        // _ => error!("No subcommand matched"),
        _ => return "No subcommand matched".to_string()
    }
}






#[derive(Deserialize)]
struct CommandRequest {
    command: String,
    sbom: String,
    vendor: String,
    product: String,
    version: String,
    api_key: String,
    method: String,
    commitment: String,
    dependency: String,
}

/// CORS Fairing to add CORS headers to all responses
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "CORS Fairing",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(rocket::http::Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(rocket::http::Header::new("Access-Control-Allow-Methods", "POST, GET, OPTIONS"));
        response.set_header(rocket::http::Header::new("Access-Control-Allow-Headers", "Content-Type"));
    }
}

#[get("/<file_name>")]
async fn download_file(file_name: &str) -> Option<NamedFile> {
    NamedFile::open(Path::new(file_name)).await.ok()
}

/// Handle OPTIONS requests for CORS preflight
#[options("/execute")]
fn options_execute() -> &'static str {
    ""
}

#[post("/execute", format = "json", data = "<request>")]
fn execute_command(request: Json<CommandRequest>) -> String {
    let command = &request.command;
    error!("command: {}", command);

    let mut args = vec!["-- ".to_string(), command.clone()];
    
    // sbom
    if &request.sbom != "" {
        args.push("--sbom".to_string());
        args.push(request.sbom.clone());
    }

    
    // vendor
    if &request.vendor != "" {
        args.push("--vendor".to_string());
        args.push(request.vendor.clone());
    }

    
    // product
    if &request.product != "" {
        args.push("--product".to_string());
        args.push(request.product.clone());
    }

    
    // version
    if &request.version != "" {
        args.push("--version".to_string());
        args.push(request.version.clone());
    }


    // api_key
    if &request.api_key != "" {
        args.push("--api-key".to_string());
        args.push(request.api_key.clone());
    }

    
    // method
    if &request.method != "" {
        args.push("--method".to_string());
        args.push(request.method.clone());
    }

    
    // commitment
    if &request.commitment != "" {
        args.push("--commitment".to_string());
        args.push(request.commitment.clone());
    }

    
    // dependency
    if &request.dependency != "" {
        args.push("--dependency".to_string());
        args.push(request.dependency.clone());
    }


    error!("args: {:?}", args);



    debug!("Parsing CLI...");
    match parse_cli(args).as_str() {
        t if command == "get_zkp" || command == "get_zkp_full" => {
            error!("t: {}", t);

            let config = load_config().unwrap();
            let path = config.app.output;
            format!("File created! <a href='{}'>Download here</a>,", path)
        }
        res => res.to_string(),
    }
}

#[get("/")]
async fn index() -> Option<NamedFile> {
    NamedFile::open(Path::new("static/index.html")).await.ok()
}


fn print_working_directory() {
    let cwd = env::current_dir().unwrap();
    println!("Current working directory: {}", cwd.display());
}

#[launch]
fn rocket() -> _ {
    init_logger();
    print_working_directory(); // Print the working directory
    debug!("Logger initialized.");

    let config = load_config().unwrap();
    let is_clean_init = config.app.clean_init_dbs;
    delete_dbs(is_clean_init);

    debug!("Initializing the databases...");
    init_dbs();

    rocket::build()
        .attach(CORS) // Attach the CORS fairing
        .mount("/", routes![index, execute_command, options_execute, download_file])
}
