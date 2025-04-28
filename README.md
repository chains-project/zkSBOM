# zkSBOM

This repository contains two proof-of-concept (PoC) implementations for disclosing limited yet verifiable SBOM information to authorized users

- [zkSBOM](./zksbom/)
- [zkSBOM Verifier](./zksbom-verifier/)



```
cd ../zksbom-verifier && cargo run -- verify_merkle --commitment "29ff88bff2498e411178507e4f9b9c477b16d183a36b4bf891e9c32440d7e44d" --proof_path "../zksbom/tmp/proof.txt" && cd ../zksbom/
```