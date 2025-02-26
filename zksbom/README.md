# zkSBOM

zkSBOM is a proof of concept (PoC) for disclosing limited but verifiable SBOM information to authorized users.

## Example Usage

### Uploading an SBOM as a Vendor

This command uploads the specified SBOM to the system.
Currently, the SBOM must include a vulnerability section, which can be generated using tools like [trivy](https://trivy.dev/).

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ./zksbom.cdx.json
```

### Retrieving a Commitment

This command fetches the generated commitment for an uploaded SBOM, if available.

```Bash
cargo run -- get_commitment --vendor "unknown" --product "zksbom" --version "0.1.0"
```

### Obtaining the Zero-Knowledge Proof (ZKP)

There are two ways to retrieve the ZKP:

1. Provide the commitment of the product to be verified.
2. Provide the vendor name, product name, and product version for verification.

Additionally, the vulnerability to be checked must be specified.

#### Retrieving ZKP Using a Commitment

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "0x1558d078686b0003e13a7a637bc7492b8f41b67ac268ad4c3867794ae9715347" --dependency "binary-merkle-tree@16.0.0"
```

#### Retrieving ZKP Using Vendor, Product Name, and Version

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "unknown" --product "alpine" --version "3.13.1" --vulnerability "CVE-2022-37434"
```
