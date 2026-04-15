#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $DIR

#######
# Setup
#######

# Remove SBOMs if present
rm -rf ./sboms

# Remove zksbom-operator DBs if present
rm -rf ../zksbom-operator/tmp

# Generate SBOMs
./scripts/generate_sboms.sh

# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release


###########################################
# Time commitment generation for every SBOM
###########################################
for file in $DIR/sboms/*; do
  ./target/release/zksbom-operator upload_sbom \
    --api-key 123 \
    --timing_analysis true \
    --sbom $file \
    --timing_analysis_output $DIR/results/create_commitment.txt \
    --only_ozks true
done


#######################
# Time proof generation
#######################
# TODO: Add timing
for file in $DIR/sboms/*; do
  ./target/release/zksbom-operator create_proof_no_commitment \
    --api-key 123 \
    --method "ozks" \
    --vendor "RQ2" \
    --product "$(basename "$file" .cdx.json)" \
    --version "0.1.0" \
    --check "CVE-2025-24898" \
    --output "./tmp/output/proof-$(basename "$file" .cdx.json).txt" 
done


#########################
# Time proof verification
#########################
# TODO: Add timing
# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release


for file in $DIR/sboms/*; do
  # Get commitment
  cd $DIR/../zksbom-operator
  commitment=$(./target/release/zksbom-operator get_commitment \
    --method "ozks" \
    --vendor "RQ2" \
    --product $(basename "$file" .cdx.json) \
    --version "0.1.0" | awk '{print $2}')
  # Verify proof
  cd $DIR/../zksbom-verifier
  ./target/release/zksbom-verifier verify \
    --method "ozks" \
    --commitment "$commitment" \
    --proof_path "../zksbom-operator/tmp/output/proof-$(basename "$file" .cdx.json).txt" 
done
