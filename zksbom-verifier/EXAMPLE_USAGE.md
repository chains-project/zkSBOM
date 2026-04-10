# Example Usage

## Merkle Trees (MT)

```Bash
target/release/zksbom-verifier verify \
--method "merkle-tree" \
--commitment "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d" \
--proof_path "../zksbom-operator/tmp/output/proof.txt"
# > Proof is valid: true
```

### Sparse Merkle Trees (SMT)

```Bash
target/release/zksbom-verifier verify \
--method "sparse-merkle-tree" \
--commitment "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51" \
--proof_path "../zksbom-operator/tmp/output/proof.txt"
# > Proof is valid: true
```

### Merkle Patricia Tries (MPT)

```Bash
target/release/zksbom-verifier verify \
--method "merkle-patricia-trie" \
--commitment "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633" \
--proof_path "../zksbom-operator/tmp/output/proof.txt"
# > Proof is valid: true
```

### Ordered Zero-Knowledge Sets (oZKS)

```Bash
target/release/zksbom-verifier verify \
--method "ozks" \
--commitment "700000001000000000000A002E002800240004000A000000D2D406073A996968E5B214CD8347177E72DB4F676B79D621EAFD5676AA4F77731000000001000000000006000800040006000000040000002000000011522CAC781A1E8B72875F5E253BFB4AFA37CC805ECFFC92571AED7E9765E6A6" \
--proof_path "../zksbom-operator/tmp/output/proof.txt"
# > Proof is valid: true
```
