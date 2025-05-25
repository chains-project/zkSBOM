# zkSBOM

zkSBOM is a proof of concept (PoC) for disclosing limited but verifiable SBOM information to authorized users.

## Building the Project

Build the project:

```Bash
cargo build --release
```

##   an SBOM as a Vendor

This command uploads the specified SBOM to the system.

```Bash
target/release/zksbom upload_sbom --api-key <api token> --sbom "<path to sbom>"
```

## Retrieving a Commitment

This command fetches the generated commitment for an uploaded SBOM, if available.

```Bash
target/release/zksbom get_commitment --vendor "<vendor>" --product "<product>" --version "<version>" --method "<method>"
```

## Trigger Dependency-Vulnerability Mapping

Ideally in a live system this should run regulary, e.g. every six hours.

```Bash
target/release/zksbom map_vulnerabilities
```

## Obtaining the Zero-Knowledge Proof (ZKP)

There are two ways to retrieve the ZKP:

1. Provide the commitment of the product to be verified.
2. Provide the vendor name, product name, and product version for verification.

Additionally, the dependency to be checked must be specified.

## Retrieving ZKP Using a Commitment

```Bash
target/release/zksbom get_zkp --api-key 123 --method "<method>" --commitment "<commitment>" --vulnerability "<vulnerability as CVE>"
```

## Retrieving ZKP Using Vendor, Product Name, and Version

```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "<method>" --vendor "<vendor>" --product "<product>" --version "<version>" --vulnerability "<vulnerability as CVE>"
```

## Possible Flags

- `--log_level`:
  - A string that specifies the log level.
  - Default: `"warn"`
- `--output`:
  - A string that specifies the path and filename for the output proof file.
  - Default: `"./tmp/output/proof.txt"`
- `--clean_init_dbs`:
  - A boolean that determines whether the databases should be deleted before running the application.
  - Default: `false`
- `--check_dependencies`:
  - A boolean that determines whether dependencies should be checked against [crates.io](https://crates.io/). This is only useful for Rust Project SBOMs.
  - Default: `false`
- `--check_dependencies_output`:
  - A string that specifies the path and filename for the output dependency check.
  - Default: `"./tmp/output/unfound_dependencies.log"`
- `--db_commitment_path`:
  - A string that specifies the path to the commitment database.
  - Default: `"./tmp/database/commitment.db"`
- `--db_sbom_path`:
  - A string that specifies the path to the SBOM database.
  - Default: `"./tmp/database/sbom.db"`
- `--db_dependency_path`:
  - A string that specifies the path to the dependency database.
  - Default: `"./tmp/database/dependency.db"`

If a flag is not specified, the default value will be used.

### Example Usage with All Flags

Setting all configurations for this command is unnecessary.
Instead, it should provide an example demonstrating the use of all possible flags.

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ../sboms/zksbom-verifier.cdx.json  --log_level "info" --output "./proof.txt" --clean_init_dbs true --check_dependencies true --check_dependencies_output "./unfound_dependencies.log" --db_commitment_path "./commitment.db" --db_sbom_path "./sbom.db" --db_dependency_path "./dependency.db"
```

## Example Usage

### Merkle Tree
```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "merkle-tree"
```
```Bash
target/release/zksbom get_zkp --api-key 123 --method "merkle-tree" --commitment "0x3c0d917514e8f20f5f8063cd874305e07f79c4988293d8ac17512901da567d35" --vulnerability "CVE-2025-24898"
```
```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "merkle-tree" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

### Sparse Merkle Tree
```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "sparse-merkle-tree"
```
```Bash
target/release/zksbom get_zkp --api-key 123 --method "sparse-merkle-tree" --commitment "0x97a3794926b6fd5b8d7c9d5df5b500fe6902eb23224b7e6b4714f107944c9efd" --vulnerability "CVE-2025-24898"
```
```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "sparse-merkle-tree" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

### Merkle Patricia Trie
```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "merkle-patricia-trie"
```
```Bash
target/release/zksbom get_zkp --api-key 123 --method "merkle-patricia-trie" --commitment "0xf672df5906e69514c0416b58461073fe4b177f285e1fe880697a95d065b10f93" --vulnerability "CVE-2025-24898"
```
```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "merkle-patricia-trie" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

### OZKS
```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "ozks"
```
```Bash
target/release/zksbom get_zkp --api-key 123 --method "ozks" --commitment "700000001000000000000A002E002800240004000A000000A4E51D09D2AF41D8EC7CF816B920B56C00BCC0F3EEDE121391FF0CBE7DD9A844100000000100000000000600080004000600000004000000200000000F9547C4E9690EBAEE24009E3EB0181ECAB390D748D54B6E3BAB412F8F30CDA0" --vulnerability "CVE-2025-24898"
```
```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "ozks" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```
