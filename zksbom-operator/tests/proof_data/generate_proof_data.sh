#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

# Always execute from zksbom-operator folder
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR"
cd ../../

# Remove DBs
rm -rf ./tmp

# Upload
cargo run -- upload_sbom \
--api-key 123 \
--sbom ./tests/sboms/druid-0.22.0.cdx.json \
--conceal false

# Inclusion Proof CVE
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mt-inclusion-proof.txt \
    --conceal false

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-inclusion-proof.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-inclusion-proof.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-inclusion-proof.txt \
    --conceal false

# Inclusion Proof Dependency
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mt-inclusion-proof-dep.txt \
    --conceal false

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-inclusion-proof-dep.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-inclusion-proof-dep.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-inclusion-proof-dep.txt \
    --conceal false

# Non Inclusion Proof CVE
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-non-inclusion-proof.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-non-inclusion-proof.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-non-inclusion-proof.txt \
    --conceal false

# Non Inclusion Proof Dependency
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-non-inclusion-proof-dep.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-non-inclusion-proof-dep.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-non-inclusion-proof-dep.txt \
    --conceal false

# Get Commitments
## MT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/mt-commitment.txt

## SMT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "sparse-merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/smt-commitment.txt

## MT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "merkle-patricia-trie" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/mpt-commitment.txt

## oZKS
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "ozks" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/ozks-commitment.txt


# Remove DBs
rm -rf ./tmp

# Upload Concealed
cargo run -- upload_sbom \
--api-key 123 \
--sbom ./tests/sboms/druid-0.22.0.cdx.json \
--conceal true

# Inclusion Proof CVE Concealed
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mt-inclusion-proof-concealed.txt \
    --conceal true

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-inclusion-proof-concealed.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-inclusion-proof-concealed.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2021-44228" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-inclusion-proof-concealed.txt \
    --conceal true

# Inclusion Proof Dependency Concealed
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mt-inclusion-proof-concealed-dep.txt \
    --conceal true

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-inclusion-proof-concealed-dep.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-inclusion-proof-concealed-dep.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "org.apache.logging.log4j:log4j-core@2.4@MAVEN" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-inclusion-proof-concealed-dep.txt \
    --conceal true

# Non Inclusion Proof CVE Concealed
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-non-inclusion-proof-concealed.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-non-inclusion-proof-concealed.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-non-inclusion-proof-concealed.txt \
    --conceal true

# Non Inclusion Proof Dependency Concealed

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/smt-non-inclusion-proof-concealed-dep.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/mpt-non-inclusion-proof-concealed-dep.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "The Apache Software Foundation" --product druid --version "0.22.0" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/druid-0.22.0.cdx.json/ozks-non-inclusion-proof-concealed-dep.txt \
    --conceal true

# Get Commitments Concealed
## MT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/mt-commitment-concealed.txt

## SMT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "sparse-merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/smt-commitment-concealed.txt

## MT
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "merkle-patricia-trie" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/mpt-commitment-concealed.txt

## oZKS
cargo run -- get_commitment \
--vendor "The Apache Software Foundation" \
--product "druid" \
--version "0.22.0" \
--method "ozks" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/druid-0.22.0.cdx.json/ozks-commitment-concealed.txt
