# Example Usage

```bash
# Upload SBOM
target/release/zksbom upload_sbom \
--api-key 123 \
--sbom "../sboms/other/test_sbom_openssl.cdx.json"
# > Uploading SBOM completed.

# Trigger Dependency-Vulnerability Mapping
target/release/zksbom map_vulnerabilities
# > Mapping dependencies and vulnerabilities completed.
```

## Merkle Trees (MT)

```bash
#  Retrieve Commitment
target/release/zksbom get_commitment \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--method "merkle-tree"
# > Commitment: 0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d

# Generate Cryptographic Proof
target/release/zksbom create_proof \
--api-key 123 \
--method "merkle-tree" \
--commitment "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d" \
--check "CVE-2025-24898"
## or:
target/release/zksbom create_proof_no_commitment \
--api-key 123 \
--method "merkle-tree" \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--check "CVE-2025-24898"
# Proof written to: ./tmp/output/proof.txt
```

## Sparse Merkle Trees (SMT)
```bash
# Retrieve Commitment
target/release/zksbom get_commitment \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--method "sparse-merkle-tree"
# > Commitment: 0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51

# Generate Cryptographic Proof
target/release/zksbom create_proof \
--api-key 123 \
--method "sparse-merkle-tree" \
--commitment "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51" \
--check "CVE-2025-24898"
## or:
target/release/zksbom create_proof_no_commitment \
--api-key 123 \
--method "sparse-merkle-tree" \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--check "CVE-2025-24898"
# > Proof written to: ./tmp/output/proof.txt
```

## Merkle Patricia Tries (MPT)

```bash
# Retrieve Commitment
target/release/zksbom get_commitment \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--method "merkle-patricia-trie"
# > Commitment: 0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633

# Generate Cryptographic Proof
target/release/zksbom create_proof \
--api-key 123 \
--method "merkle-patricia-trie" \
--commitment "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633" \
--check "CVE-2025-24898"
## or:
target/release/zksbom create_proof_no_commitment \
--api-key 123 \
--method "merkle-patricia-trie" \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--check "CVE-2025-24898"
# > Proof written to: ./tmp/output/proof.txt
```

## Ordered Zero-Knowledge Sets (oZKS)

```bash
# Retrieve Commitment
target/release/zksbom get_commitment \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--method "ozks"
# > Commitment: 700000001000000000000A002E002800240004000A000000D2D406073A996968E5B214CD8347177E72DB4F676B79D621EAFD5676AA4F77731000000001000000000006000800040006000000040000002000000011522CAC781A1E8B72875F5E253BFB4AFA37CC805ECFFC92571AED7E9765E6A6

# Generate Cryptographic Proof
target/release/zksbom create_proof \
--api-key 123 \
--method "ozks" \
--commitment "700000001000000000000A002E002800240004000A000000D2D406073A996968E5B214CD8347177E72DB4F676B79D621EAFD5676AA4F77731000000001000000000006000800040006000000040000002000000011522CAC781A1E8B72875F5E253BFB4AFA37CC805ECFFC92571AED7E9765E6A6" \
--check "CVE-2025-24898"
## or:
target/release/zksbom create_proof_no_commitment \
--api-key 123 \
--method "ozks" \
--vendor "Tom Sorger <sorger@kth.se>" \
--product "test_openssl" \
--version "0.1.0" \
--check "CVE-2025-24898"
# > Proof written to: ./tmp/output/proof.txt
```
