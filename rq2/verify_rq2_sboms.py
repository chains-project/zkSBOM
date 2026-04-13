import json
from pathlib import Path


def load_sbom(json_file: Path) -> dict:
    """Parse a single SBOM JSON file and return its data."""
    with open(json_file, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_expected_count(data: dict) -> int:
    """Extract the expected component count from the metadata name field."""
    name = data["metadata"]["component"]["name"]
    return int(name)


def count_components(data: dict) -> int:
    """Count the actual number of components in the SBOM."""
    return len(data.get("components", []))


def validate_sbom(json_file: Path) -> dict:
    """
    Validate a single SBOM file by comparing the expected component count
    (encoded in the metadata name) to the actual number of components.

    Returns a result dict with keys: file, expected, actual, match, error.
    """
    result = {"file": json_file.name, "expected": None, "actual": None, "match": False, "error": None}

    try:
        data = load_sbom(json_file)
        result["expected"] = extract_expected_count(data)
        result["actual"] = count_components(data)
        result["match"] = result["expected"] == result["actual"]

    except (KeyError, TypeError) as e:
        result["error"] = f"Missing or malformed field: {e}"
    except ValueError as e:
        result["error"] = f"Could not parse metadata name as integer: {e}"
    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON: {e}"

    return result


def validate_all_sboms(sboms_dir: str = "sboms") -> list[dict]:
    """
    Validate all JSON files found in the given directory.

    Returns a list of result dicts, one per file.
    """
    sboms_path = Path(sboms_dir)

    if not sboms_path.is_dir():
        raise FileNotFoundError(f"Directory '{sboms_dir}' not found.")

    json_files = sorted(sboms_path.glob("*.json"))

    if not json_files:
        raise FileNotFoundError(f"No JSON files found in '{sboms_dir}'.")

    return [validate_sbom(f) for f in json_files]


def print_report(results: list[dict]) -> None:
    """Print a human-readable validation report and an overall pass/fail summary."""
    passed = [r for r in results if r["match"]]
    failed = [r for r in results if not r["match"] and not r["error"]]
    errored = [r for r in results if r["error"]]

    total = len(results)

    print(f"\n{'='*52}")
    print(f"  SBOM Validation Report  ({total} file{'s' if total != 1 else ''})")
    print(f"{'='*52}")

    if failed or errored:
        if failed:
            print(f"\nMismatches ({len(failed)}):")
            for r in failed:
                print(
                    f"   - {r['file']}: "
                    f"expected {r['expected']} component{'s' if r['expected'] != 1 else ''}, "
                    f"found {r['actual']}"
                )

        if errored:
            print(f"\nErrors ({len(errored)}):")
            for r in errored:
                print(f"   - {r['file']}: {r['error']}")

        if passed:
            print(f"\nPassed ({len(passed)}):")
            for r in passed:
                print(f"   - {r['file']} ({r['actual']} component{'s' if r['actual'] != 1 else ''})")
    else:
        print(f"\nAll {total} file{'s' if total != 1 else ''} passed validation.")
        for r in passed:
            print(f"   - {r['file']} ({r['actual']} component{'s' if r['actual'] != 1 else ''})")

    print(f"\n{'='*52}")
    print(f"  Result: {len(passed)} passed / {len(failed)} failed / {len(errored)} errored")
    print(f"{'='*52}\n")


def main():
    try:
        results = validate_all_sboms("sboms")
    except FileNotFoundError as e:
        print(f"\n{e}")
        return

    print_report(results)

    # Exit with a non-zero code if any file failed or errored — useful in CI
    all_passed = all(r["match"] for r in results)
    if not all_passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
