#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------
# Configuration
# -------------------------------------------------------
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBOMS_DIR="../sboms"
GENERATE_SCRIPT="./create_dummy_data.py"
VERIFY_SCRIPT="verify_rq2_sboms.py"

# The component counts you want to generate.
# Each number N produces a file called <NNN>.cdx.json with N components.
COUNTS=(0 10 30 50 100 150 200 250 300 350 400 450 500)

# -------------------------------------------------------
# Checks
# -------------------------------------------------------
cd $DIR
for script in "$GENERATE_SCRIPT" "$VERIFY_SCRIPT"; do
  if [[ ! -f "$script" ]]; then
    echo "Required script not found: $script"
    exit 1
  fi
done

# -------------------------------------------------------
# Generate SBOMs
# -------------------------------------------------------
echo "Creating '$SBOMS_DIR/' directory..."
mkdir -p "$SBOMS_DIR"

echo "Generating ${#COUNTS[@]} SBOM file(s)..."
for count in "${COUNTS[@]}"; do
  filename=$(printf "%03d" "$count").cdx.json
  output_path="$SBOMS_DIR/$filename"

  python3 "$GENERATE_SCRIPT" --sbom "$count" > "$output_path"
  echo "$output_path  ($count component(s))"
done

# -------------------------------------------------------
# Verify SBOMs
# -------------------------------------------------------
echo ""
echo "Running verification..."
echo ""
cd $DIR
python3 "$VERIFY_SCRIPT"
