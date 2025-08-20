# Zero-Knowledge SBOM - zkSBOM

This repository contains a proof-of-concept (PoC) implementation for disclosing limited yet verifiable SBOM information to authorized users using cryptographic methods.
Supported cryptographic methods are Merkle Trees (MT), Sparse Merkle Trees (SMT), Merkle Patricia Tries (MPT), and Ordered Zero-Knowledge Sets (oZKS).

## zkSBOM

[zkSBOM](./zksbom/) is used for vendors to upload their product SBOMs to the system, customers to retrieve a commitment for a specific SBOM, as well as generating cryptographic proofs that specific vulnerable dependencies are present within the SBOM.
It also triggers regular dependency-vulnerability mappings.

## zkSBOM Verifier

[zkSBOM Verifier](./zksbom-verifier/) is used for verifying the generated proof of zkSBOM.

## Installation

To install this project simply clone the repository:

```Bash
git clone git@github.com:chains-project/zkSBOM.git
```

After cloning the repository, you must configure the project.
For that, copy the configuration template and modify its content.

```Bash
cp zksbom/config/config_template.toml zksbom/config/config.toml
```

Now modify the [configuration file](zksbom/config/config.toml) to have your [personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) (PAT) from your GitHub account as `github_token`.
This token will be used to query the [GitHub Advisory Database](https://github.com/advisories).

## Execution

#### Build zkSBOM

Navigate to the `zksbom` project:

```Bash
cd zksbom
```

Build the project in release mode using `cargo`:

```Bash
cargo build --release
```

#### Upload SBOM

After building the project you can start upload SBOMs the system:

```Bash
target/release/zksbom upload_sbom --api-key <api key> --sbom "<path to sbom>"
```

The systems uses all cryptographic methods to create all commitments for the SBOM.
In this PoC, the parameter for the `api-key` is mandatory, but its value is not being checked by the system.

> [!IMPORTANT]  
> To use `oZKS` you currently have to start the server for it yourself.
> For that, start the executable at `zksbom/src/method/ozks/ozks-server.exe`.
> This executable is the result of the oZKS submodule at `zksbom/src/method/ozks/dev`.  
> Using `oZKS` is at the moment not persistent and only works for `target_arch = "x86_64"` (tested on Win11).

#### Retrieve Commitment

After uploading an SBOM to the system, you can retrieve its commitment:

```Bash
target/release/zksbom get_commitment --vendor "<vendor>" --product "<product>" --version "<version>" --method "<method>"
```

Where `vendor` is the vendor of the SBOM, `product` stands for the name of the product represented by the SBOM, `verison` the version of the product represented by the SBOM, and `method` represents the cryptographic method from which the commitment, representing the SBOM, will be looked up.

> [!NOTE]  
> Supported cryptographic methods:
>
> - `merkle-tree`
> - `sparse-merkle-tree`
> - `merkle-patricia-trie`
> - `ozks`


#### Trigger Dependency-Vulnerability Mapping

Before you can generate a cryptographic proof, you must update the mapping of dependencies and vulnerabilities of the internal databases:

```Bash
target/release/zksbom map_vulnerabilities
```

In a live system this would ideally run regulary, e.g. every six hours.

> [!IMPORTANT]  
> In case this command doesn't find any vulnerabilities even tough it should, make sure that your [personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) (PAT) from your GitHub is correclt configured in the [config file](zksbom/config/config.toml).

#### Generate Cryptographic Proof

In the next step, you can generate a cryptographic proof for a specific vulnerability for a given commitment.
This can be done in two ways; the first one using a commitment:

```Bash
target/release/zksbom get_zkp --api-key <api key> --method "<method>" --commitment "<commitment>" --vulnerability "<CVE>"
```

Where `api-key` stands again for a mandatory api-key that is currently not being checked by the system, `method` for the cryptographic method that should be used, `commitment` for the previously retrieved commitment, and `vulnerability` for the vulnerbility that we want to generate a proof for represented by its CVE.

Or using the product vendor, product name, and product version instead of the commitment:

```Bash
target/release/zksbom get_zkp_full --api-key <api key> --method "<method>" --vendor "<vendor>" --product "<product>" --version "<version>" --vulnerability "<vulnerability as CVE>"
```

> [!TIP]
> Concrete examples and snippets can be found in the `zksbom` [README](./zksbom/README.md).

#### Build zkSBOM Verifier

Navigate to the `zksbom-verifier` project:

```Bash
cd zksbom-verifier
```

Build the project in release mode using `cargo`:

```Bash
cargo build --release
```

#### Verify Cryptographic Proof

After generating a cryptographic proof, we can now use the verifier to verify wether the asked for vulnerability is present in the SBOM.

```Bash
target/release/zksbom-verifier verify --method "<method>" --commitment "<commitment>" --proof_path "<proof path>"
```

Where `method` describes the cryptographic method that shoiuld be used, `commitment` stands for the commitment of the SBOM, and `proof_path` for the path to the proof file.

> [!TIP]
> Concrete examples and snippets can be found in the `zksbom-verifier` [README](./zksbom-verifier/README.md).
