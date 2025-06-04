use crate::config::load_config;
use crate::database::db_dependency::get_dependencies;
use crate::map_dependencies_vulnerabilities::get_mapping_for_dependencies;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use core::panic;
use log::debug;
use log::error;
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, traits::Value, CompiledMerkleProof,
    SparseMerkleTree, H256,
};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

// define SMT
type SMT = SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>;

// define SMT value
#[derive(Default, Clone)]
pub struct Word(String);
impl Value for Word {
    fn to_h256(&self) -> H256 {
        if self.0.is_empty() {
            return H256::zero();
        }
        let mut buf = [0u8; 32];
        let mut hasher = new_blake2b();
        hasher.update(self.0.as_bytes());
        hasher.finalize(&mut buf);
        buf.into()
    }
    fn zero() -> Self {
        Default::default()
    }
}

// helper function
fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn blake2b_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap(); // 32 bytes output
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize_variable(&mut output).unwrap();
    output
}

fn build_key_and_leaf(name: &str) -> ([u8; 32], [u8; 32]) {
    let key = blake2b_hash(name.as_bytes());
    let mut concat = Vec::from(key);
    concat.extend_from_slice(name.as_bytes());
    let leaf = blake2b_hash(&concat);
    (key, leaf)
}

fn get_kv(leaf: &str) -> (H256, H256) {
    let kv = build_key_and_leaf(&leaf);
    return (H256::from(kv.0), H256::from(kv.1));
}

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    let mut tree = SMT::default();

    for dependency in dependencies {
        let (key, leaf) = get_kv(&dependency);
        debug!("key: {:?}, leaf: {:?}", key, leaf);
        tree.update(key, leaf).expect("update");
    }

    if tree.is_empty() {
        panic!("Sparse Merkle Tree is empty.");
    }

    let root = tree.root().clone();
    debug!("Sparse Merkle Tree Commitment: {:?}.", &root);

    let commitment = format!("0x{}", hex::encode(root.as_slice()));
    debug!("Sparse Merkle Tree Commitment hex: {}", &commitment);

    return commitment;
}

fn generate_proof(
    commitment: &str,
    dependencies: Vec<&str>,
    dependency: String,
) -> (String, String) {
    // check if dependency exists
    if let Some(_) = dependencies.iter().position(|&leaf| leaf == dependency) {
        debug!("Dependency found");
    } else {
        panic!("Dependency not found");
    };

    // update tree
    let mut tree = SMT::default();

    for dep in dependencies {
        let (key, leaf) = get_kv(&dep);
        debug!("key: {:?}, leaf: {:?}", key, leaf);
        tree.update(key, leaf).expect("update");
    }

    // create proof for the dependency
    if tree.is_empty() {
        panic!("Sparse Merkle Tree is empty.");
    }

    let root = tree.root().clone();
    let commitment_tree = format!("0x{}", hex::encode(root.as_slice()));
    if commitment_tree != commitment {
        panic!("Commitment mismatch SMT");
    }

    let (key, _) = get_kv(&dependency);

    let now = Instant::now();
    let proof = tree.merkle_proof(vec![key]).expect("proof");
    let compiled_proof: CompiledMerkleProof =
        proof.clone().compile(vec![key]).expect("compile proof");
    let elapsed = now.elapsed();
    debug!("Compiled proof for key: {:?}", compiled_proof);

    debug!("Inside proof: {:?}", compiled_proof.0.as_slice());
    let compiled_proof_hex = format!("0x{}", hex::encode(compiled_proof.0.as_slice()));
    debug!("Compiled Proof hex: {}", &compiled_proof_hex);

    return (compiled_proof_hex, elapsed.as_nanos().to_string());
}

pub fn create_proof(commitment: &str, vulnerability: &str) -> String {
    let dependency_entry = get_dependencies(commitment.to_string(), "sparse-merkle-tree");
    let dependencies: Vec<&str> = dependency_entry.dependencies.split(",").collect();
    let dep_vul_map = get_mapping_for_dependencies(dependencies.clone());

    for dep in dependencies.clone() {
        let stripped_dep = dep.split(';').next().unwrap_or(dep);
        if dep_vul_map.contains_key(stripped_dep) {
            if dep_vul_map[stripped_dep].contains(&vulnerability.to_string()) {
                debug!("Dependency: {} is vulnerable to: {}", dep, vulnerability);
                let (proof, elapsed) = generate_proof(commitment, dependencies, dep.to_string());
                print_proof(proof, dep.to_string());
                return elapsed;
            }
        }
    }
    return "".to_string();
}

fn print_proof(proof: String, dependency: String) {
    let config = load_config().unwrap();
    let output_path = config.app.output;

    let path = Path::new(&output_path);
    if let Some(parent) = path.parent() {
        if let Err(e) = create_dir_all(parent) {
            error!("Error creating directory: {}", e);
            return;
        }
    }

    let mut file = match File::create(&output_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error creating file: {}", e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "Proof: {}", proof) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "Leaf: {}", dependency) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.") {
        error!("Error writing to file: {}", e);
        return;
    }

    let (key, value) = get_kv(&dependency);

    let key_hex = format!("0x{}", hex::encode(key.as_slice()));
    let value_hex = format!("0x{}", hex::encode(value.as_slice()));

    if let Err(e) = writeln!(file, "Key: {}", key_hex) {
        error!("Error writing to file: {}", e);
        return;
    }

    if let Err(e) = writeln!(file, "Value: {}", value_hex) {
        error!("Error writing to file: {}", e);
        return;
    }

    println!("Proof written to: {}", output_path);
}
