# zksbom

## Command Examples

```Bash
cargo run -- upload_sbom --api-key 123 --sbom ./test/sbom/example.cdx.json
```

```Bash
cargo run -- get_commitment --vendor "aquasecurity" --product "trivy" --version "0.36.1"
```

```Bash
cargo run -- get_zkp --api-key 123 --method "Merkle Tree" --commitment "0x28e2f187d92d3816d0f1a207bf91b9af427d731ef4abea59e510b4952ea109e3" --vulnerability "CVE-2022-37434"
```

```Bash
cargo run -- get_zkp_full --api-key 123 --method "Merkle Tree" --vendor "My Vendor" --product "My Product" --version "My Verison" --vulnerability "A vulnerability"
```
