use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use log::debug;
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, traits::Value, SparseMerkleTree, H256,
};

type SMT = SparseMerkleTree<Blake2bHasher, H256, DefaultStore<H256>>;

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

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"SMT").build()
}

fn blake2b_hash(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
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
    let kv = build_key_and_leaf(leaf);
    (H256::from(kv.0), H256::from(kv.1))
}

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    debug!("create commitment; dependencies: {:?}", dependencies);
    let mut tree = SMT::default();
    for dependency in dependencies {
        let (key, leaf) = get_kv(&dependency);
        tree.update(key, leaf).expect("update");
    }
    if tree.is_empty() {
        panic!("Sparse Merkle Tree is empty.");
    }
    format!("0x{}", hex::encode(tree.root().as_slice()))
}

pub fn generate_formatted_proof(
    commitment: &str,
    dependencies: Vec<&str>,
    dependency: &str,
) -> String {
    let mut tree = SMT::default();
    for dep in dependencies {
        let (key, leaf) = get_kv(dep);
        tree.update(key, leaf).expect("update");
    }

    if format!("0x{}", hex::encode(tree.root().as_slice())) != commitment {
        panic!("Commitment mismatch SMT");
    }

    let (key, value) = get_kv(dependency);
    let proof = tree.merkle_proof(vec![key]).expect("proof");
    let compiled_proof = proof.compile(vec![key]).expect("compile proof");

    let proof_hex = format!("0x{}", hex::encode(compiled_proof.0.as_slice()));
    let key_hex = format!("0x{}", hex::encode(key.as_slice()));
    let value_hex = format!("0x{}", hex::encode(value.as_slice()));

    let formatted_payload = format!(
        "Proof: {}\nLeaf: {}\n# Hashes input bytes using the Blake2b algorithm with the dependency as `key` and the `key || dependency` as value, then storing as HEX.\nKey: {}\nValue: {}",
        proof_hex, dependency, key_hex, value_hex
    );

    formatted_payload
}
