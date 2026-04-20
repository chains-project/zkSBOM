#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $DIR

INCLUSION_CVE="CVE-2021-44228"
NON_INCLUSION_CVE="CVE-2025-55182"

#########
# Setup #
#########

# Remove SBOMs if present
rm -rf ./sboms > /dev/null 2>&1

# Remove previous results
rm ./results/synthetic/create-commitment.csv > /dev/null 2>&1
rm ./results/synthetic/create-inclusion-proofs.csv > /dev/null 2>&1
rm ./results/synthetic/create-non-inclusion-proofs.csv > /dev/null 2>&1
rm ./results/synthetic/verify-inclusion-proofs.csv > /dev/null 2>&1
rm ./results/synthetic/verify-non-inclusion-proofs.csv > /dev/null 2>&1
rm ./results/synthetic/db-size-bytes.csv > /dev/null 2>&1
rm ./results/synthetic/inclusion-proof-size-bytes.csv > /dev/null 2>&1
rm ./results/synthetic/non-inclusion-proof-size-bytes.csv > /dev/null 2>&1
rm ./results/synthetic/results.txt > /dev/null 2>&1

# Generate SBOMs
./scripts/generate_sboms.sh

# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release

# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release


for i in {1..10}; do
    echo "Iteration $i is running..."

    for file in $DIR/sboms/*; do
        echo "  Handling SBOM '$file'"
    
        #------------#
        #-- Timing --#
        #------------#

        ###############
        # Time Upload #
        ###############
        cd $DIR/../zksbom-operator
        # Remove zksbom-operator DBs if present
        rm -rf ./tmp
        ./target/release/zksbom-operator upload_sbom \
            --timing_analysis true \
            --timing_analysis_output $DIR/results/synthetic/create-commitment.csv \
            --api-key 123 \
            --sbom $file \
            --only_ozks true > /dev/null 2>&1
        
        ##################
        # Get commitment #
        ##################
        commitment=$(./target/release/zksbom-operator get_commitment \
            --method "ozks" \
            --vendor "RQ2" \
            --product $(basename "$file" .cdx.json) \
            --version "0.1.0" | awk '{print $2}')

        ############################
        # Generate inclusion proof #
        ############################
        ./target/release/zksbom-operator create_proof \
            --timing_analysis_output $DIR/results/synthetic/create-inclusion-proofs.csv \
            --timing_analysis true \
            --api-key 123 \
            --method "ozks" \
            --commitment $commitment \
            --check "$INCLUSION_CVE" \
            --output "./tmp/output/inclusion-proof-$(basename "$file" .cdx.json).txt" > /dev/null 2>&1
        
        ################################
        # Generate non-inclusion proof #
        ################################
        ./target/release/zksbom-operator create_proof \
            --timing_analysis_output $DIR/results/synthetic/create-non-inclusion-proofs.csv \
            --timing_analysis true \
            --api-key 123 \
            --method "ozks" \
            --commitment $commitment \
            --check "$NON_INCLUSION_CVE" \
            --output "./tmp/output/non-inclusion-proof-$(basename "$file" .cdx.json).txt" > /dev/null 2>&1
        
        ##########################
        # Verify inclusion proof #
        ##########################
        cd $DIR/../zksbom-verifier
        ./target/release/zksbom-verifier verify \
            --timing_analysis_output $DIR/results/synthetic/verify-inclusion-proofs.csv \
            --timing_analysis true \
            --method "ozks" \
            --commitment "$commitment" \
            --proof_path "../zksbom-operator/tmp/output/inclusion-proof-$(basename "$file" .cdx.json).txt" > /dev/null 2>&1
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS requires the empty string argument
                sed -i '' "$ s/$/,$(basename "$file" .cdx.json)/" "$DIR/results/synthetic/verify-inclusion-proofs.csv"
            else
                # Linux (GNU) does NOT want the empty string argument
                sed -i "$ s/$/,$(basename "$file" .cdx.json)/" "$DIR/results/synthetic/verify-inclusion-proofs.csv"
            fi
        
        ##############################
        # Verify non-inclusion proof #
        ##############################
        cd $DIR/../zksbom-verifier
        ./target/release/zksbom-verifier verify \
            --timing_analysis_output $DIR/results/synthetic/verify-non-inclusion-proofs.csv \
            --timing_analysis true \
            --method "ozks" \
            --commitment "$commitment" \
            --proof_path "../zksbom-operator/tmp/output/non-inclusion-proof-$(basename "$file" .cdx.json).txt" > /dev/null 2>&1
            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS requires the empty string argument
                sed -i '' "$ s/$/,$(basename "$file" .cdx.json)/" "$DIR/results/synthetic/verify-non-inclusion-proofs.csv"
            else
                # Linux (GNU) does NOT want the empty string argument
                sed -i "$ s/$/,$(basename "$file" .cdx.json)/" "$DIR/results/synthetic/verify-non-inclusion-proofs.csv"
            fi

        #-------------#
        #-- Storage --#
        #-------------#

        ############
        # Database #
        ############
        cd "$DIR/../zksbom-operator/tmp/database"

        ALL_DB_SIZE=0
        for db_file in $DIR/../zksbom-operator/tmp/database/*; do
        
            # Skip if it's a directory
            [ -f "$db_file" ] || continue

            if [[ "$OSTYPE" == "darwin"* ]]; then
                # macOS / BSD
                SIZE=$(stat -f%z "$db_file")
            else
                # Linux / GNU
                SIZE=$(stat -c%s "$db_file")
            fi

             # Use (( )) for arithmetic
            (( ALL_DB_SIZE += SIZE ))
        done
       
        echo "ozks,$ALL_DB_SIZE,$(basename "$file" .cdx.json)" >> $DIR/results/synthetic/db-size-bytes.csv

        #####################
        # Proof file sizes #
        ####################
        cd "$DIR/../zksbom-operator/tmp/output"

        for proof_file in $DIR/../zksbom-operator/tmp/output/*; do
            [ -f "$proof_file" ] || continue

            filename=$(basename "$proof_file")

            if [[ "$filename" == non-inclusion-proof* ]]; then
                if [[ "$OSTYPE" == "darwin"* ]]; then
                    SIZE=$(stat -f%z "$proof_file")
                else
                    SIZE=$(stat -c%s "$proof_file")
                fi
                echo "ozks,$SIZE,$(basename "$file" .cdx.json)" >> $DIR/results/synthetic/non-inclusion-proof-size-bytes.csv

            elif [[ "$filename" == inclusion-proof* ]]; then
               if [[ "$filename" == inclusion-proof-0000* ]]; then
                    continue
                else
                    if [[ "$OSTYPE" == "darwin"* ]]; then
                        SIZE=$(stat -f%z "$proof_file")
                    else
                        SIZE=$(stat -c%s "$proof_file")
                    fi
                    echo "ozks,$SIZE,$(basename "$file" .cdx.json)" >> $DIR/results/synthetic/inclusion-proof-size-bytes.csv
                fi
            fi
        done

        # Remove zksbom-operator DBs and output files
        rm -rf ../zksbom-operator/tmp
    done
done

#################
# Analyse Results
#################
cd $DIR
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Create Commitment --------------------------" >> ./results/synthetic/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/synthetic/create-commitment.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Create Inclusion Proof ---------------------" >> ./results/synthetic/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/synthetic/create-inclusion-proofs.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Create Non-Inclusion Proof -----------------" >> ./results/synthetic/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/synthetic/create-non-inclusion-proofs.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Verify Inclsuion Proof ---------------------" >> ./results/synthetic/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/synthetic/verify-inclusion-proofs.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Verify Non-Inclsuion Proof -----------------" >> ./results/synthetic/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/synthetic/verify-non-inclusion-proofs.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- DB Sizes------------------ -----------------" >> ./results/synthetic/results.txt 2>&1
 python3 ./scripts/analyse_size.py ./results/synthetic/db-size-bytes.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Inclusion Proof Sizes ----------------------" >> ./results/synthetic/results.txt 2>&1
 python3 ./scripts/analyse_size.py ./results/synthetic/inclusion-proof-size-bytes.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
echo "--- Non-Inclusion Proof Sizes ------------------" >> ./results/synthetic/results.txt 2>&1
 python3 ./scripts/analyse_size.py ./results/synthetic/non-inclusion-proof-size-bytes.csv >> ./results/synthetic/results.txt 2>&1
echo "------------------------------------------------" >> ./results/synthetic/results.txt 2>&1
