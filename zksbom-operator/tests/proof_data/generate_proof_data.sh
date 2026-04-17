#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status


# Prompt the user for their name
read -p "Enter the SBOM name (e.g., 'druid-0.22.0.cdx.json'; note: the SBOM must be in the '../sboms' folder): " sbom_name

case "$sbom_name" in
  "druid-0.22.0.cdx.json")
    vendor="The Apache Software Foundation"
    product="druid"
    version="0.22.0"
    check_cve="CVE-2021-44228"
    check_dep="org.apache.logging.log4j:log4j-core@2.4@MAVEN"
    ;;
  "strapi.cdx.json")
    vendor="Strapi Solutions SAS"
    product="strapi"
    version="unknown"
    check_cve="CVE-2023-22621"
    check_dep="@strapi/plugin-email@4.4.4@NPM"
    ;;
  *)
    # The default/fallback case (wildcard)
    echo "Unknown environment. Setting defaults."
    ;;
esac




# Always execute from zksbom-operator folder
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
cd "$SCRIPT_DIR"
cd ../../

# Remove DBs
rm -rf ./tmp

# Upload
cargo run -- upload_sbom \
--api-key 123 \
--sbom ./tests/sboms/$sbom_name \
--conceal false

# Inclusion Proof CVE
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/mt-inclusion-proof.txt \
    --conceal false

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/smt-inclusion-proof.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/mpt-inclusion-proof.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/ozks-inclusion-proof.txt \
    --conceal false

# Inclusion Proof Dependency
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/mt-inclusion-proof-dep.txt \
    --conceal false

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/smt-inclusion-proof-dep.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/mpt-inclusion-proof-dep.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/ozks-inclusion-proof-dep.txt \
    --conceal false

# Non Inclusion Proof CVE
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/smt-non-inclusion-proof.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/mpt-non-inclusion-proof.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/ozks-non-inclusion-proof.txt \
    --conceal false

# Non Inclusion Proof Dependency
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/smt-non-inclusion-proof-dep.txt \
    --conceal false

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/mpt-non-inclusion-proof-dep.txt \
    --conceal false

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/ozks-non-inclusion-proof-dep.txt \
    --conceal false

# Get Commitments
## MT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/mt-commitment.txt

## SMT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "sparse-merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/smt-commitment.txt

## MT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "merkle-patricia-trie" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/mpt-commitment.txt

## oZKS
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "ozks" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/ozks-commitment.txt


# Remove DBs
rm -rf ./tmp

# Upload Concealed
cargo run -- upload_sbom \
--api-key 123 \
--sbom ./tests/sboms/$sbom_name \
--conceal true

# Inclusion Proof CVE Concealed
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/mt-inclusion-proof-concealed.txt \
    --conceal true

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/smt-inclusion-proof-concealed.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/mpt-inclusion-proof-concealed.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_cve" \
    --output ./tests/proof_data/$sbom_name/ozks-inclusion-proof-concealed.txt \
    --conceal true

# Inclusion Proof Dependency Concealed
## MT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/mt-inclusion-proof-concealed-dep.txt \
    --conceal true

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/smt-inclusion-proof-concealed-dep.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/mpt-inclusion-proof-concealed-dep.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "$check_dep" \
    --output ./tests/proof_data/$sbom_name/ozks-inclusion-proof-concealed-dep.txt \
    --conceal true

# Non Inclusion Proof CVE Concealed
## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/smt-non-inclusion-proof-concealed.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/mpt-non-inclusion-proof-concealed.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "CVE-2025-55182" \
    --output ./tests/proof_data/$sbom_name/ozks-non-inclusion-proof-concealed.txt \
    --conceal true

# Non Inclusion Proof Dependency Concealed

## SMT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "sparse-merkle-tree" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/smt-non-inclusion-proof-concealed-dep.txt \
    --conceal true

## MPT
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "merkle-patricia-trie" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/mpt-non-inclusion-proof-concealed-dep.txt \
    --conceal true

## oZKS
cargo run -- create_proof_no_commitment \
    --api-key "123" \
    --method "ozks" \
    --vendor "$vendor" --product "$product" --version "$version" \
    --check "foo@0.0.1@foo" \
    --output ./tests/proof_data/$sbom_name/ozks-non-inclusion-proof-concealed-dep.txt \
    --conceal true

# Get Commitments Concealed
## MT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/mt-commitment-concealed.txt

## SMT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "sparse-merkle-tree" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/smt-commitment-concealed.txt

## MT
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "merkle-patricia-trie" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/mpt-commitment-concealed.txt

## oZKS
cargo run -- get_commitment \
--vendor "$vendor" \
--product "$product" \
--version "$version" \
--method "ozks" \
| sed -n 's/.*Commitment: //p' \
| tr -d '\n' > ./tests/proof_data/$sbom_name/ozks-commitment-concealed.txt
