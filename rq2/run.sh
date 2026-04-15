#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $DIR

INCLUSION_CVE="CVE-2021-44228"
NON_INCLUSION_CVE="CVE-2025-55182"

# #######
# # Setup
# #######

# Remove SBOMs if present
rm -rf ./sboms

# Remove previous results
rm ./results/create-commitment.csv
rm ./results/create-inclusion-proofs.csv
rm ./results/create-non-inclusion-proofs.csv
rm ./results/verify-inclusion-proofs.csv
rm ./results/verify-non-inclusion-proofs.csv
rm ./results/results.txt

# Generate SBOMs
./scripts/generate_sboms.sh

# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release

# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release


for i in {1..10}; do
    # Remove zksbom-operator DBs if present
    rm -rf ../zksbom-operator/tmp

    ###########################################
    # Time commitment generation for every SBOM
    ###########################################
    cd $DIR/../zksbom-operator
    for file in $DIR/sboms/*; do
    ./target/release/zksbom-operator upload_sbom \
        --timing_analysis true \
        --timing_analysis_output $DIR/results/create-commitment.csv \
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
    # Generate inclusion proof
    ./target/release/zksbom-operator create_proof \
        --timing_analysis_output $DIR/results/create-inclusion-proofs.csv \
        --timing_analysis true \
        --api-key 123 \
        --method "ozks" \
        --commitment $commitment \
        --check "$INCLUSION_CVE" \
        --output "./tmp/output/inclusion-proof-$(basename "$file" .cdx.json).txt"
    # Generate non-inclusion proof
    ./target/release/zksbom-operator create_proof \
        --timing_analysis_output $DIR/results/create-non-inclusion-proofs.csv \
        --timing_analysis true \
        --api-key 123 \
        --method "ozks" \
        --commitment $commitment \
        --check "$NON_INCLUSION_CVE" \
        --output "./tmp/output/non-inclusion-proof-$(basename "$file" .cdx.json).txt" 
    done


    #########################
    # Time proof verification
    #########################
    for file in $DIR/sboms/*; do
    # Inclusion proof
    ## Get commitment
    cd $DIR/../zksbom-operator
    commitment=$(./target/release/zksbom-operator get_commitment \
        --method "ozks" \
        --vendor "RQ2" \
        --product $(basename "$file" .cdx.json) \
        --version "0.1.0" | awk '{print $2}')
    # Verify inclusion proof
    cd $DIR/../zksbom-verifier
    ./target/release/zksbom-verifier verify \
        --timing_analysis_output $DIR/results/verify-inclusion-proofs.csv \
        --timing_analysis true \
        --method "ozks" \
        --commitment "$commitment" \
        --proof_path "../zksbom-operator/tmp/output/inclusion-proof-$(basename "$file" .cdx.json).txt"
        sed -i '' "$ s/$/,$(basename "$file" .cdx.json)/" $DIR/results/verify-inclusion-proofs.csv
    ## Verify non-inclusion proof
    cd $DIR/../zksbom-verifier
    ./target/release/zksbom-verifier verify \
        --timing_analysis_output $DIR/results/verify-non-inclusion-proofs.csv \
        --timing_analysis true \
        --method "ozks" \
        --commitment "$commitment" \
        --proof_path "../zksbom-operator/tmp/output/non-inclusion-proof-$(basename "$file" .cdx.json).txt"
        sed -i '' "$ s/$/,$(basename "$file" .cdx.json)/" $DIR/results/verify-non-inclusion-proofs.csv
    done


done

#################
# Analyse Results
#################
cd $DIR
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "--- Create Commitment --------------------------" >> ./results/results.txt 2>&1
python3 ./scripts/analyse_results.py ./results/create-commitment.csv >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "--- Create Inclusion Proof ---------------------" >> ./results/results.txt 2>&1
python3 ./scripts/analyse_results.py ./results/create-inclusion-proofs.csv >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "--- Create Non-Inclusion Proof -----------------" >> ./results/results.txt 2>&1
python3 ./scripts/analyse_results.py ./results/create-non-inclusion-proofs.csv >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "--- Verify Inclsuion Proof ---------------------" >> ./results/results.txt 2>&1
python3 ./scripts/analyse_results.py ./results/verify-inclusion-proofs.csv >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
echo "--- Verify Non-Inclsuion Proof -----------------" >> ./results/results.txt 2>&1
python3 ./scripts/analyse_results.py ./results/verify-non-inclusion-proofs.csv >> ./results/results.txt 2>&1
echo "------------------------------------------------" >> ./results/results.txt 2>&1
