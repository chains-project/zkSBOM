use sha2::{Sha256, Digest};
use base64::encode;

pub fn generate_proof() {
    println!("Hello, world!");
}

pub fn verify_proof() {
    println!("Hello, world!");
}

// a, b, c, d, e, f, g, h
// a+b, c+d, e+f, g+h
// a+b+c+d, e+f+g+h
// a+b+c+d+e+f+g+h
pub fn generate_tree(input: Vec<String> ) {
    let leaf_count = input.len();


    for element in input {
        println!("{}", element);
        let element_hash = sha256_hash(&element);
        println!("{}", element_hash);
    }
}

fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes()); // Convert string to bytes
    let result = hasher.finalize();

    // Convert the raw hash bytes to a Base64-encoded string
    encode(result)
}

#[derive(Debug, Clone)]
struct MerkleTree {
    root: String, // a+b+c+d+e+f+g+h
    leaves: Vec<String>, // a, b, c, d, e, f, g, h
    tree: Vec<Vec<Vec<String>>>, // [[a], [b], [c], [d], [e], [f], [g], [h], [a, b], [c, d], [e, f], [g, h], [a+b, c+d, e+f, g+h], [a+b+c+d, e+f+g+h], [a+b+c+d+e+f+g+h]]
}






// / https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf
// / Jellyfish Whitepaper
// / 