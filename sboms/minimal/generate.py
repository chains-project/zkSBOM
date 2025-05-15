import requests
import json

REGISTRIES = [
    {
        "ecosystem": "cargo",
        "url": "https://crates.io/api/v1/crates",
        "purl_prefix": "pkg:cargo/"
    },
    {
        "ecosystem": "maven",
        "url": "https://search.maven.org/solrsearch/select",
        "purl_prefix": "pkg:maven/"
    },
]

def fetch_crates(limit):
    resp = requests.get(f"{REGISTRIES[0]['url']}?page=11&per_page={limit}")
    crates = resp.json()["crates"]
    out = []
    for crate in crates:
        name = crate["id"]
        version = crate["max_stable_version"] or crate["newest_version"]
        purl = f"{REGISTRIES[0]['purl_prefix']}{name}@{version}"
        out.append({"type": "library", "name": name, "version": version, "purl": purl})
    return out

def fetch_maven(limit):
    params = {"q": "*:*", "rows": limit, "wt": "json"}
    resp = requests.get(REGISTRIES[1]["url"], params=params).json()
    docs = resp["response"]["docs"]
    out = []
    for d in docs:
        group = d["g"]
        artifact = d["a"]
        version = d["latestVersion"]
        name = f"{group}:{artifact}"
        purl = f"{REGISTRIES[1]['purl_prefix']}{group}/{artifact}@{version}"
        out.append({"type": "library", "name": name, "version": version, "purl": purl})
    return out

def main():
    print("Generating SBOM with minimal data...")
    desired = 64
    per_registry = {
        "cargo": 32,
        "maven": 32
    }
    sbom = []
    sbom.extend(fetch_crates(per_registry["cargo"]))
    sbom.extend(fetch_maven(per_registry["maven"]))

    if len(sbom) > desired:
        sbom = sbom[:desired]
    elif len(sbom) < desired:
        pass

    print(json.dumps(sbom, indent=4))
    print(f"total: {len(sbom)}, desired: {desired}")

if __name__ == "__main__":
    main()
