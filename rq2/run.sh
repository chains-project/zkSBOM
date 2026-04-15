#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate SBOMs
./scripts/generate_sboms.sh

# Build zksbom-operator
cd $DIR
cd ../zksbom-operator
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

cd $DIR

#######################
# Time proof generation
#######################



#########################
# Time proof verification
#########################

