# zkSBOM

zkSBOM is a proof of concept (PoC) for disclosing limited but verifiable SBOM information to authorized users.

## Example Usage

### Uploading an SBOM as a Vendor

This command uploads the specified SBOM to the system.
Currently, the SBOM must include a vulnerability section, which can be generated using tools like [trivy](https://trivy.dev/).

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ../sboms/valid_sbom-1.4_trivy-0.36.1_alpine-3.13.1.cdx.json
```

### Retrieving a Commitment

This command fetches the generated commitment for an uploaded SBOM, if available.

```Bash
cargo run -- get_commitment --vendor "unknown" --product "alpine" --version "3.13.1"
```

### Obtaining the Zero-Knowledge Proof (ZKP)

There are two ways to retrieve the ZKP:

1. Provide the commitment of the product to be verified.
2. Provide the vendor name, product name, and product version for verification.

Additionally, the vulnerability to be checked must be specified.

#### Retrieving ZKP Using a Commitment

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "0x28e2f187d92d3816d0f1a207bf91b9af427d731ef4abea59e510b4952ea109e3" --vulnerability "CVE-2022-37434"
```

#### Retrieving ZKP Using Vendor, Product Name, and Version

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "unknown" --product "alpine" --version "3.13.1" --vulnerability "CVE-2022-37434"
```
