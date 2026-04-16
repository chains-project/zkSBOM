#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
SBOM_DIR="${1:-sbom-files}"

count_total=0
count_skipped_not_json=0
count_skipped_not_cyclonedx=0
count_processed=0
count_errors=0
count_skipped_too_large=0


# ------------------------------------------------------------------------------
# Main loop — recurse into subdirectories
# ------------------------------------------------------------------------------
while IFS= read -r -d '' file; do
    (( count_total++ )) || true

    # Skip non-JSON files
    if ! file --mime-type "$file" | grep -q "application/json"; then
        # echo "[SKIP] Not a JSON file: $file"
        (( count_skipped_not_json++ )) || true
        continue
    fi

    # Skip JSON files that are not CycloneDX SBOMs
    if ! grep -q '"bomFormat"\s*:\s*"CycloneDX"' "$file" 2>/dev/null; then
        # echo "[SKIP] Not a CycloneDX SBOM: $file"
        (( count_skipped_not_cyclonedx++ )) || true
        continue
    fi

    # Skip SBOMs thaat have more than 1.000 components
    # This is because we only have our syntethic benchmark until up to 1.000.
    component_count=$(jq '.components | length' "$file" 2>/dev/null)
    if [[ "$component_count" -gt 1000 ]]; then
        echo "[SKIP] Too many components ($component_count): $file"
        (( count_skipped_too_large++ )) || true
        continue
    fi

    # Process the file — catch errors and continue
    echo "[FOUND] $file, with $component_count components."

done < <(find "$SBOM_DIR" -type f -print0)

# ------------------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------------------
echo ""
echo "=============================="
echo " Results"
echo "=============================="
echo "  Total files found             : $count_total"
echo "  Skipped (not JSON)            : $count_skipped_not_json"
echo "  Skipped (not CycloneDX)       : $count_skipped_not_cyclonedx"
echo "  Skipped (too many components) : $count_skipped_too_large"
echo "  Processed                     : $count_processed"
echo "  Errors                        : $count_errors"
echo "=============================="
