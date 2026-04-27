use crate::hasher::hash_h256_kv;
use reference_trie::NoExtensionLayout;
use trie_db::{
    proof::generate_proof as generate_proof_trie, DBValue, TrieDBMutBuilder, TrieLayout, TrieMut,
};

type MemoryDB<T> = memory_db::MemoryDB<
    <T as TrieLayout>::Hash,
    memory_db::HashKey<<T as TrieLayout>::Hash>,
    DBValue,
>;

pub fn create_commitment(dependencies: Vec<&str>) -> String {
    let mut db = <MemoryDB<NoExtensionLayout>>::default();
    let mut root = Default::default();
    {
        let mut trie = <TrieDBMutBuilder<NoExtensionLayout>>::new(&mut db, &mut root).build();
        for (key, value) in hash_h256_kv(dependencies) {
            trie.insert(key.as_bytes(), value.as_bytes()).unwrap();
        }
    }
    format!("0x{}", hex::encode(root))
}

pub fn generate_formatted_proof(
    commitment: &str,
    dependencies: Vec<&str>,
    dependency: &str,
) -> String {
    let mut db = <MemoryDB<NoExtensionLayout>>::default();
    let mut root = Default::default();
    {
        let mut trie = <TrieDBMutBuilder<NoExtensionLayout>>::new(&mut db, &mut root).build();
        for (key, value) in hash_h256_kv(dependencies) {
            trie.insert(key.as_bytes(), value.as_bytes()).unwrap();
        }
    }

    if format!("0x{}", hex::encode(&root)) != commitment {
        panic!("Commitment mismatch MPT");
    }

    let kv = hash_h256_kv(vec![dependency]);
    let key_u8 = kv.get(0).unwrap().0.as_bytes();
    let key = vec![key_u8];

    let proof = generate_proof_trie::<_, NoExtensionLayout, _, _>(&db, &root, &key).unwrap();

    let mut proof_hex = String::new();
    for proof_item in &proof {
        proof_hex.push_str(&format!("0x{};", hex::encode(proof_item)));
    }
    proof_hex = proof_hex.trim_end_matches(';').to_string();

    let target_key_hex = format!("0x{}", hex::encode(kv.get(0).unwrap().0));
    let target_value_hex = format!("0x{}", hex::encode(kv.get(0).unwrap().1));

    let formatted_payload = format!(
        "Proof: {}\nLeaf: {}\n# The Key is the Keccak-256 hash of the dependency string, and the Value is the Keccak-256 hash of the same dependency string, both of which are used as the key-value pair inserted into the Merkle Patricia Trie and can be recomputed by hashing the leaf dependency with the hash function.\nKey: {}\nValue: {}",
        proof_hex, dependency, target_key_hex, target_value_hex
    );

    formatted_payload
}
