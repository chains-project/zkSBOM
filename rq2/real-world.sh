#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
SBOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sbom-files2" # TODO: change
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INCLUSION_CVE="CVE-2021-44228"
NON_INCLUSION_CVE="CVE-2025-55182"

count_total=0
count_skipped_not_json=0
count_skipped_not_cyclonedx=0
count_found_good_sboms=0
count_errors=0
count_skipped_too_large=0


# Remove previous results
rm ./results/real-world/create-commitment.csv > /dev/null 2>&1
rm ./results/real-world/db-size-bytes.csv > /dev/null 2>&1
rm ./results/real-world/results.txt > /dev/null 2>&1
rm ./results/real-world/results-overview.txt > /dev/null 2>&1


# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release

# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release

cd $SBOM_DIR
# ------------------------------------------------------------------------------
# Main loop — recurse into subdirectories
# ------------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    (( count_total++ )) || true

    # ------------------------------------------------------------------------------
    # Filter out unusable SBOMs
    # ------------------------------------------------------------------------------
    # Skip non-JSON files
    if ! file --mime-type "$file" | grep -q "application/json"; then
        (( count_skipped_not_json++ )) || true
        continue
    fi

    # Skip JSON files that are not CycloneDX SBOMs
    if ! grep -q '"bomFormat"\s*:\s*"CycloneDX"' "$file" 2>/dev/null; then
        (( count_skipped_not_cyclonedx++ )) || true
        continue
    fi

    # Skip SBOMs thaat have more than 1.000 components
    # This is because we only have our syntethic benchmark until up to 1.000.
    component_count=$(jq '.components | length' "$file" 2>/dev/null)
    if [[ "$component_count" -gt 1000 ]]; then
        (( count_skipped_too_large++ )) || true
        continue
    fi

    # ------------------------------------------------------------------------------
    # Run functional SBOM
    # ------------------------------------------------------------------------------
    (( count_found_good_sboms++ )) || true
    echo "Handling SBOM '$file'"

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
        --timing_analysis_output $DIR/results/real-world/create-commitment.csv \
        --api-key 123 \
        --sbom $file \
        --only_ozks true > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "  WARN: upload_sbom failed, skipping..."
        (( count_errors++ )) || true
        continue
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
    
    echo "ozks,$ALL_DB_SIZE,$component_count" >> $DIR/results/real-world/db-size-bytes.csv

done < <(find "$SBOM_DIR" -type f -print0)

#################
# Analyse Results
#################
cd $DIR
echo "------------------------------------------------" >> ./results/real-world/results.txt 2>&1
echo "--- Create Commitment --------------------------" >> ./results/real-world/results.txt 2>&1
python3 ./scripts/analyse_time.py ./results/real-world/create-commitment.csv >> ./results/real-world/results.txt 2>&1
echo "------------------------------------------------" >> ./results/real-world/results.txt 2>&1
echo "------------------------------------------------" >> ./results/real-world/results.txt 2>&1
echo "--- DB Sizes------------------ -----------------" >> ./results/real-world/results.txt 2>&1
python3 ./scripts/analyse_size.py ./results/real-world/db-size-bytes.csv >> ./results/real-world/results.txt 2>&1
echo "------------------------------------------------" >> ./results/real-world/results.txt 2>&1

# ------------------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------------------
echo "==============================" >> ./results/real-world/results-overview.txt 2>&1
echo " Results" >> ./results/real-world/results-overview.txt 2>&1
echo "==============================" >> ./results/real-world/results-overview.txt 2>&1
echo "  Total files found             : $count_total" >> ./results/real-world/results-overview.txt 2>&1
echo "  Skipped (not JSON)            : $count_skipped_not_json" >> ./results/real-world/results-overview.txt 2>&1
echo "  Skipped (not CycloneDX)       : $count_skipped_not_cyclonedx" >> ./results/real-world/results-overview.txt 2>&1
echo "  Skipped (too many components) : $count_skipped_too_large" >> ./results/real-world/results-overview.txt 2>&1
echo "  Found good SBOMs              : $count_found_good_sboms" >> ./results/real-world/results-overview.txt 2>&1
echo "  Errors                        : $count_errors" >> ./results/real-world/results-overview.txt 2>&1
echo "==============================" >> ./results/real-world/results-overview.txt 2>&1
