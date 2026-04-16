import json
import sys


def make_components(count: int) -> list[dict]:
    """
    Factory function that generates a list of dummy component entries.

    Args:
        count: Number of components to generate.

    Returns:
        A list of component dicts with sequential names starting from 1.
    """
    return [
        {
            "type": "library",
            "name": str(i),
            "version": "0.1.0",
            "purl": f"pkg:cargo/{i}@0.1.0",
        }
        for i in range(1, count + 1)
    ]


def make_sbom(count: int) -> dict:
    """
    Factory function that generates a full SBOM document.

    The metadata name is zero-padded to 3 digits (e.g. 0 -> "000", 10 -> "010"),
    matching the filename convention used for verification.

    Args:
        count: Number of components to include.

    Returns:
        A full SBOM dict with metadata and components list.
    """
    return {
        "metadata": {
            "component": {
                "author": "RQ2",
                "name": f"{count:04d}",
                "version": "0.1.0",
            }
        },
        "components": make_components(count),
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python generate_dummy_data.py <count>           # components only")
        print("  python generate_dummy_data.py --sbom <count>    # full SBOM document")
        sys.exit(1)

    sbom_mode = sys.argv[1] == "--sbom"
    count_arg = sys.argv[2] if sbom_mode else sys.argv[1]

    try:
        count = int(count_arg)
    except ValueError:
        print(f"Error: '{count_arg}' is not a valid integer.")
        sys.exit(1)

    if count < 0:
        print("Error: count must be 0 or greater.")
        sys.exit(1)

    data = make_sbom(count) if sbom_mode else make_components(count)
    print(json.dumps(data, indent=2))
