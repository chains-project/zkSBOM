# zksbom

## Command Examples

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ../sboms/valid_sbom-1.4_trivy-0.36.1_alpine-3.13.1.cdx.json
```

```Bash
cargo run -- get_commitment --vendor "unknown" --product "alpine" --version "3.13.1"
```

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "0x2dd347128a9c6985f96ec6fc3c790ac1c2ad4c3e2fdec1da4da8d81efac950e4" --vulnerability "CVE-2022-37434"
```

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "My Vendor" --product "My Product" --version "My Verison" --vulnerability "A vulnerability"
```

```Bash
cargo fmt
```
