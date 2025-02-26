# zkSBOM

zkSBOM is a proof of concept (PoC) for disclosing limited but verifiable SBOM information to authorized users.

## Example Usage

### Uploading an SBOM as a Vendor

This command uploads the specified SBOM to the system.
Currently, the SBOM must include a vulnerability section, which can be generated using tools like [trivy](https://trivy.dev/).

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ../sboms/zksbom-verifier.cdx.json
```

### Retrieving a Commitment

This command fetches the generated commitment for an uploaded SBOM, if available.

```Bash
cargo run -- get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "zksbom-verifier" --version "0.1.0"
```

### Obtaining the Zero-Knowledge Proof (ZKP)

There are two ways to retrieve the ZKP:

1. Provide the commitment of the product to be verified.
2. Provide the vendor name, product name, and product version for verification.

Additionally, the vulnerability to be checked must be specified.

#### Retrieving ZKP Using a Commitment

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "0x0b9a83b952a61d281939e463e0848058e80271e4d2db5d294e4b7e8194276447" --dependency "binary-merkle-tree@16.0.0"
```

#### Retrieving ZKP Using Vendor, Product Name, and Version

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "Tom Sorger <sorger@kth.se>" --product "zksbom-verifier" --version "0.1.0" --dependency "binary-merkle-tree@16.0.0"
```
