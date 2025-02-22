# Demo

## Commands

### Upload

Upload a SBOM to the private DB.

```Rust
RUST_LOG=debug cargo run -- upload --sbom ./input/simple_example.json --vendor example_vendor --product example_product --version 1.2
```

### Get Commitment

Get a commitment from the public DB.

```Rust
RUST_LOG=debug cargo run -- get-commitment --vendor example_vendor --product example_product --version 1.2
```

### Get ZKP

Get the ZKP.

```Rust
RUST_LOG=debug cargo run -- get-zk-proof --help
```

### Verify

Verify the ZKP.
(Will probably be moved to another app; so it is a verifier only.)

```Rust
RUST_LOG=debug cargo run -- verify --help
```
