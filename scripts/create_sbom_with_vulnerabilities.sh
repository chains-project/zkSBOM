#!/bin/bash

# Output file for cargo cyclonedx
cyclonedx_output="tmp.cdx"

# Output file for trivy sbom (accepting as a parameter)
trivy_output="$1"
echo "trivy_output: $trivy_output"

# Check if the trivy output file is provided
if [ -z "$trivy_output" ]; then
  echo "Usage: $0 <trivy_output_file>"
  exit 1
fi

# Run cargo cyclonedx
cargo cyclonedx -f json --override-filename "$cyclonedx_output"

# Check if cargo cyclonedx was successful
if [ $? -ne 0 ]; then
  echo "Error: cargo cyclonedx failed"
  exit 1
fi

# Run trivy sbom
trivy sbom --format cyclonedx --output "$trivy_output" "$cyclonedx_output".json

# Check if trivy sbom was successful
if [ $? -ne 0 ]; then
  echo "Error: trivy sbom failed"
  exit 1
fi

# Remove the temporary cyclonedx file
rm "$cyclonedx_output".json

echo "SBOM generation complete."
echo "SBOM with vulnerabilities: $trivy_output"
