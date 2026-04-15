#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $DIR

# #######
# # Setup
# #######

# Remove SBOMs if present
rm -rf ./sboms

# Remove previous results
rm ./results/create_commitment.csv
rm ./results/create_proofs.csv
rm ./results/verify_proofs.csv
rm ./results/results.txt

# Generate SBOMs
./scripts/generate_sboms.sh

# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release

# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release


for i in {1..2}; do
    # Remove zksbom-operator DBs if present
    rm -rf ../zksbom-operator/tmp

    ###########################################
    # Time commitment generation for every SBOM
    ###########################################
    cd $DIR/../zksbom-operator
    for file in $DIR/sboms/*; do
    ./target/release/zksbom-operator upload_sbom \
        --timing_analysis true \
        --timing_analysis_output $DIR/results/create_commitment.csv \
        --api-key 123 \
        --sbom $file \
        --only_ozks true
    done


    #######################
    # Time proof generation
    #######################
    for file in $DIR/sboms/*; do
    # Get commitment
    commitment=$(./target/release/zksbom-operator get_commitment \
        --method "ozks" \
        --vendor "RQ2" \
        --product $(basename "$file" .cdx.json) \
        --version "0.1.0" | awk '{print $2}')
    # Generate proof
    ./target/release/zksbom-operator create_proof \
        --timing_analysis_output $DIR/results/create_proofs.csv \
        --timing_analysis true \
        --api-key 123 \
        --method "ozks" \
        --commitment $commitment \
        --check "CVE-2025-24898" \
        --output "./tmp/output/proof-$(basename "$file" .cdx.json).txt" 
    done


    #########################
    # Time proof verification
    #########################
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
        --timing_analysis_output $DIR/results/verify_proofs.csv \
        --timing_analysis true \
        --method "ozks" \
        --commitment "$commitment" \
        --proof_path "../zksbom-operator/tmp/output/proof-$(basename "$file" .cdx.json).txt"
        sed -i "$ s/$/,$(basename "$file" .cdx.json)/" $DIR/results/verify_proofs.csv
    done


done

#################
# Analyse Results
#################
cd $DIR
echo "------------------------------------------------" >> ./results/result.txt 2>&1
echo "--- Create Commitment --------------------------" >> ./results/result.txt 2>&1
python3 ./scripts/analyse_results.py ./results/create_commitment.csv >> ./results/result.txt 2>&1
echo "------------------------------------------------" >> ./results/result.txt 2>&1
echo "------------------------------------------------" >> ./results/result.txt 2>&1
echo "--- Create Proof -------------------------------" >> ./results/result.txt 2>&1
python3 ./scripts/analyse_results.py ./results/create_proofs.csv >> ./results/result.txt 2>&1
echo "------------------------------------------------" >> ./results/result.txt 2>&1
echo "------------------------------------------------" >> ./results/result.txt 2>&1
echo "--- Verify Proof -------------------------------" >> ./results/result.txt 2>&1
python3 ./scripts/analyse_results.py ./results/verify_proofs.csv >> ./results/result.txt 2>&1
echo "------------------------------------------------" >> ./results/result.txt 2>&1
