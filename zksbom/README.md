# zkSBOM

zkSBOM allows vendors to upload their product SBOMs, customers to retrieve commitments for specific SBOMs, and the system to generate cryptographic proofs confirming the presence of vulnerable dependencies.
It also automatically performs regular dependency-to-vulnerability mapping updates.

## Examples

The examples in this README are not generic but show detailed examples.
For a more generic description, please have a look at the initial [README](../README.md).

### Build zkSBOM

```Bash
cargo build --release
```

### Upload SBOM

```Bash
target/release/zksbom upload_sbom --api-key 123 --sbom "../sboms\other\test_sbom_openssl.cdx.json"
```

### Trigger Dependency-Vulnerability Mapping

```Bash
target/release/zksbom map_vulnerabilities
```

### Example: Merkle Trees (MT)

#### Retrieve Commitment

```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "merkle-tree"
```

> [!NOTE]
> Expected output:  
> `Commitment: 0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d`

#### Generate Cryptographic Proof

```Bash
target/release/zksbom get_zkp --api-key 123 --method "merkle-tree" --commitment "0x29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d" --vulnerability "CVE-2025-24898"
```
 Or:

```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "merkle-tree" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

> [!NOTE]
> Expected output:  
> `Proof written to: ./tmp/output/proof.txt`

### Example: Sparse Merkle Trees (SMT)

#### Retrieve Commitment

```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "sparse-merkle-tree"
```

> [!NOTE]
> Expected output:  
> `Commitment: 0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51`

#### Generate Cryptographic Proof

```Bash
target/release/zksbom get_zkp --api-key 123 --method "sparse-merkle-tree" --commitment "0xdb6bbe76d4b256a389baac6675c9650bfd9d097f9b4789437346b3aeb8864b51" --vulnerability "CVE-2025-24898"
```

Or:

```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "sparse-merkle-tree" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

> [!NOTE]
> Expected output:  
> `Proof written to: ./tmp/output/proof.txt`








### Example: Merkle Patricia Tries (MPT)

#### Retrieve Commitment

```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "merkle-patricia-trie"
```

> [!NOTE]
> Expected output:  
> `Commitment: 0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633`

#### Generate Cryptographic Proof

```Bash
target/release/zksbom get_zkp --api-key 123 --method "merkle-patricia-trie" --commitment "0x850ae2b766052239536e1a4e5de35947508ce88bc9c500f71d1940aa7404c633" --vulnerability "CVE-2025-24898"
```

Or:

```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "merkle-patricia-trie" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

> [!NOTE]
> Expected output:  
> `Proof written to: ./tmp/output/proof.txt`

### Example: Ordered Zero-Knowledge Sets (oZKS)

#### Retrieve Commitment

```Bash
target/release/zksbom get_commitment --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --method "ozks"
```

> [!NOTE]
> Expected output similar to:  
> `Commitment: 700000001000000000000A002E002800240004000A000000D2D406073A996968E5B214CD8347177E72DB4F676B79D621EAFD5676AA4F77731000000001000000000006000800040006000000040000002000000011522CAC781A1E8B72875F5E253BFB4AFA37CC805ECFFC92571AED7E9765E6A6`

#### Generate Cryptographic Proof

```Bash
target/release/zksbom get_zkp --api-key 123 --method "ozks" --commitment "700000001000000000000A002E002800240004000A000000D2D406073A996968E5B214CD8347177E72DB4F676B79D621EAFD5676AA4F77731000000001000000000006000800040006000000040000002000000011522CAC781A1E8B72875F5E253BFB4AFA37CC805ECFFC92571AED7E9765E6A6" --vulnerability "CVE-2025-24898"
```

Or:

```Bash
target/release/zksbom get_zkp_full --api-key 123 --method "ozks" --vendor "Tom Sorger <sorger@kth.se>" --product "test_openssl" --version "0.1.0" --vulnerability "CVE-2025-24898"
```

> [!NOTE]
> Expected output:  
> `Proof written to: ./tmp/output/proof.txt`

<!--
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
-->
