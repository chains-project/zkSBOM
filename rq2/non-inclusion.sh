#!/usr/bin/env bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd $DIR

SCRIPT="non-inclusion-proof.py"

rm -rf ./results/non-inclusion-variation/

# Build zksbom-operator
cd $DIR/../zksbom-operator
cargo build --release

# Build zksbom-verifier
cd $DIR/../zksbom-verifier
cargo build --release


echo "Running..."
cd $DIR/../zksbom-operator
rm -rf ./tmp
python3 -u "$DIR/scripts/$SCRIPT"



# Remove third column of the CSV, as its the info about how many components are in the SBOM (which is always 1,000)
remove_sbom_count() {
    local input_file="$1"
    local temp_file=$(mktemp) # Create a secure temp file
    
    if [[ ! -f "$input_file" ]]; then
        echo "Error: File '$input_file' not found."
        return 1
    fi

    # Redirect to temp file, then move it back
    cut -d',' -f1,2,4- "$input_file" > "$temp_file" && mv "$temp_file" "$input_file"
}

cd $DIR/results/non-inclusion-variation/
remove_sbom_count ./create-proof.csv




