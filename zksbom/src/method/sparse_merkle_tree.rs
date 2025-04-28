use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use blake2b_rs::{Blake2b, Blake2bBuilder};
use log::debug;
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, traits::Value, SparseMerkleTree, H256,
};

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

// fn generate_proof(root: String, dependency: String) -> String {
//     return String::new();
// }

pub fn create_proof(_commitment: &str, _vulnerability: &str) {
    return;
}

// fn print_merkle_proof(proof: String, dependency: String) {
//     println!("Proof written to: {}", "output_path");
// }
