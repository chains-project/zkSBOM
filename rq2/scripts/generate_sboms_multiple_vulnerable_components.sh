#!/usr/bin/env python3
"""
Generates 73 SBOM files from a base ./1000.cdx.json.

File N (00001.cdx.json … 00073.cdx.json) contains exactly N components
from the fixed 73-entry list injected into the base SBOM, replacing
components that are NOT themselves on the list.
"""

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# The 73 fixed list entries (version + purl)
# ---------------------------------------------------------------------------
LIST_ENTRIES = [
    # pax-logging-log4j2  2.0.x
    {"version": "2.0.0",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.0"},
    {"version": "2.0.1",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.1"},
    {"version": "2.0.2",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.2"},
    {"version": "2.0.3",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.3"},
    {"version": "2.0.4",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.4"},
    {"version": "2.0.5",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.5"},
    {"version": "2.0.6",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.6"},
    {"version": "2.0.7",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.7"},
    {"version": "2.0.8",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.8"},
    {"version": "2.0.9",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.9"},
    {"version": "2.0.10", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@2.0.10"},
    # pax-logging-log4j2  1.11.x
    {"version": "1.11.0", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.0"},
    {"version": "1.11.1", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.1"},
    {"version": "1.11.2", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.2"},
    {"version": "1.11.3", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.3"},
    {"version": "1.11.4", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.4"},
    {"version": "1.11.5", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.5"},
    {"version": "1.11.6", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.6"},
    {"version": "1.11.7", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.7"},
    {"version": "1.11.8", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.8"},
    {"version": "1.11.9", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.11.9"},
    # pax-logging-log4j2  1.10.x
    {"version": "1.10.0", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.0"},
    {"version": "1.10.1", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.1"},
    {"version": "1.10.2", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.2"},
    {"version": "1.10.3", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.3"},
    {"version": "1.10.4", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.4"},
    {"version": "1.10.5", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.5"},
    {"version": "1.10.6", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.6"},
    {"version": "1.10.7", "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.10.7"},
    # pax-logging-log4j2  1.8.x
    {"version": "1.8.0",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.0"},
    {"version": "1.8.1",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.1"},
    {"version": "1.8.2",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.2"},
    {"version": "1.8.3",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.3"},
    {"version": "1.8.4",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.4"},
    {"version": "1.8.5",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.5"},
    {"version": "1.8.6",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.6"},
    {"version": "1.8.7",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.8.7"},
    # pax-logging-log4j2  1.9.x
    {"version": "1.9.0",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.9.0"},
    {"version": "1.9.1",  "purl": "pkg:maven/org.ops4j.pax.logging:pax-logging-log4j2@1.9.1"},
    # log4j-core
    {"version": "2.0-beta9",    "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0-beta9"},
    {"version": "2.0-rc1",      "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0-rc1"},
    {"version": "2.0-rc2",      "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0-rc2"},
    {"version": "2.0",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0"},
    {"version": "2.0.1",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0.1"},
    {"version": "2.0.2",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.0.2"},
    {"version": "2.1",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.1"},
    {"version": "2.2",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.2"},
    {"version": "2.3",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.3"},
    {"version": "2.6.3-CUSTOM", "purl": "pkg:maven/uk.co.nichesolutions.logging.log4j:log4j-core@2.6.3-CUSTOM"},
    {"version": "2.4",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.4"},
    {"version": "2.4.1",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.4.1"},
    {"version": "2.5",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.5"},
    {"version": "2.6",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.6"},
    {"version": "2.6.1",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.6.1"},
    {"version": "2.6.2",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.6.2"},
    {"version": "2.7",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.7"},
    {"version": "2.8",          "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.8"},
    {"version": "2.8.1",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.8.1"},
    {"version": "2.8.2",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.8.2"},
    {"version": "2.9.0",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.9.0"},
    {"version": "2.9.1",        "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.9.1"},
    {"version": "2.10.0",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.10.0"},
    {"version": "2.11.0",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.11.0"},
    {"version": "2.11.1",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.11.1"},
    {"version": "2.11.2",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.11.2"},
    {"version": "2.12.0",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.12.0"},
    {"version": "2.12.1",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.12.1"},
    {"version": "2.13.0",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.13.0"},
    {"version": "2.13.1",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.13.1"},
    {"version": "2.13.2",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.13.2"},
    {"version": "2.13.3",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.13.3"},
    {"version": "2.14.0",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.0"},
    {"version": "2.14.1",       "purl": "pkg:maven/org.apache.logging.log4j:log4j-core@2.14.1"},
]

assert len(LIST_ENTRIES) == 73, f"Expected 73 entries, got {len(LIST_ENTRIES)}"


# ---------------------------------------------------------------------------
# Build a minimal CycloneDX component object from a list entry
# ---------------------------------------------------------------------------
def make_component(entry: dict) -> dict:
    purl: str = entry["purl"]
    version: str = entry["version"]
    # purl format:  pkg:maven/GROUP:NAME@VERSION  (or GROUP/NAME for some)
    coords = purl.removeprefix("pkg:maven/").split("@")[0]
    if ":" in coords:
        group, name = coords.split(":", 1)
    else:
        group, name = "", coords
    return {
        "type": "library",
        "bom-ref": purl,
        "group": group,
        "name": name,
        "version": version,
        "purl": purl,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    base_path = Path("./1000.cdx.json")
    output_dir = Path("../sboms")

    if not base_path.exists():
        sys.exit(f"ERROR: base SBOM not found at {base_path}")

    print(f"Loading base SBOM from {base_path} …")
    with base_path.open() as fh:
        base_sbom = json.load(fh)

    components: list = base_sbom.get("components", [])
    if len(components) < 1000:
        sys.exit(f"ERROR: base SBOM is not the one with 1,000 components.")

    # Collect the purls that belong to our injection list so we never touch them
    list_purls: set[str] = {e["purl"] for e in LIST_ENTRIES}

    # Indices of components that are safe to replace (not already on the list)
    safe_indices = [
        i for i, c in enumerate(components)
        if c.get("purl", "") not in list_purls
    ]

    if len(safe_indices) < 73:
        sys.exit(
            f"ERROR: only {len(safe_indices)} components are safe to replace "
            f"(need 73). Reduce the injection list or use a larger base SBOM."
        )

    # Use the first 73 safe slots — deterministic, reproducible
    replace_indices = safe_indices[:73]

    # Pre-build all 73 component objects
    inject_components = [make_component(e) for e in LIST_ENTRIES]

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating 73 SBOM files into {output_dir} …\n")
    for n in range(1, 74):
        # Deep-copy the base SBOM for each file
        sbom = json.loads(json.dumps(base_sbom))
        comps: list = sbom["components"]

        formatted_n = f"{int(n):05d}"
        sbom["metadata"]["component"]["name"] = formatted_n
        # Inject the first N list components, each replacing a safe slot
        for i in range(n):
            comps[replace_indices[i]] = inject_components[i]

        sbom["components"] = comps

        out_path = output_dir / f"{n:05d}.cdx.json"
        with out_path.open("w") as fh:
            json.dump(sbom, fh, indent=2)

        print(f"  {out_path}  — {n} list component(s) injected")

    print(f"\nDone. {73} files written to {output_dir}/")


if __name__ == "__main__":
    main()