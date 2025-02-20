# zksbom

## Command Examples

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ./test/sbom/example.cdx.json
```

```Bash
cargo run -- get_commitment --vendor "vendor" --product "product" --version "version"
```

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "My Commitment" --vulnerability "A vulnerability"
```

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "My Vendor" --product "My Product" --version "My Verison" --vulnerability "A vulnerability"
```
