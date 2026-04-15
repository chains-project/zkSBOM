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
COUNTS=(0 10 30 50 100 150 200 250 300 350 400 450 500 550 600 650 700 750 800 850 900 950 1000)

OPENSSL_ENTRY='{
    "type" : "library",
      "bom-ref" : "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.2?type=jar",
      "publisher" : "The Apache Software Foundation",
      "group" : "org.apache.logging.log4j",
      "name" : "log4j-core",
      "version" : "2.8.2",
      "description" : "The Apache Log4j Implementation",
      "scope" : "required",
      "hashes" : [
        {
          "alg" : "MD5",
          "content" : "4a5177a172764bda6f4472b94ba17ccb"
        },
        {
          "alg" : "SHA-1",
          "content" : "979fc0cf8460302e4ffbfe38c1b66a99450b0bb7"
        },
        {
          "alg" : "SHA-256",
          "content" : "10ef331115cbbd18b5be3f3761e046523f9c95c103484082b18e67a7c36e570c"
        },
        {
          "alg" : "SHA-512",
          "content" : "9b28b3c19aa66f9e86362114282a5fe4b9965fadba04d5fea14832a268fe2c5bfaaceca666fb904d2d9f44dc751857c137b6772d91a40bcfd677c957d75f9b59"
        },
        {
          "alg" : "SHA-384",
          "content" : "d61703250ff1c5890923a0544179493a7b752d22e7dea58948073f9073aabfa13cecb38a2dade5734f5ee2f194b66e80"
        }
      ],
      "licenses" : [
        {
          "license" : {
            "id" : "Apache-2.0"
          }
        }
      ],
      "purl" : "pkg:maven/org.apache.logging.log4j/log4j-core@2.8.2?type=jar",
      "externalReferences" : [
        {
          "type" : "website",
          "url" : "https://logging.apache.org/log4j/2.x/log4j-core/"
        },
        {
          "type" : "build-system",
          "url" : "https://builds.apache.org/job/Log4j%202.x/"
        },
        {
          "type" : "distribution",
          "url" : "https://logging.apache.org/log4j/2.x/download.html"
        },
        {
          "type" : "distribution-intake",
          "url" : "https://repository.apache.org/service/local/staging/deploy/maven2"
        },
        {
          "type" : "issue-tracker",
          "url" : "https://issues.apache.org/jira/browse/LOG4J2"
        },
        {
          "type" : "mailing-list",
          "url" : "https://lists.apache.org/list.html?log4j-user@logging.apache.org"
        },
        {
          "type" : "vcs",
          "url" : "https://git-wip-us.apache.org/repos/asf?p=logging-log4j2.git;a=summary/log4j-core"
        }
      ]
}'

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

  # Replace one random component with the openssl entry (skip if no components)
  python3 - "$output_path" <<PYEOF
import json, random, sys

path = sys.argv[1]
entry = $OPENSSL_ENTRY

with open(path) as f:
    sbom = json.load(f)

components = sbom.get("components", [])
if components:
    idx = random.randrange(len(components))
    components[idx] = entry
    sbom["components"] = components
    with open(path, "w") as f:
        json.dump(sbom, f, indent=2)
PYEOF

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