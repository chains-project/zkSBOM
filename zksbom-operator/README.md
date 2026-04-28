# zkSBOM Operator

zkSBOM Operator allows vendors to upload their product SBOMs, customers to retrieve commitments for specific SBOMs, and the system to generate cryptographic proofs confirming the presence of vulnerable dependencies.
It also automatically performs dependency-to-vulnerability mappings.

## Installation

- Copy and edit the configuration file:

```Bash
cp ./config/config_template.toml ./config/config.toml
```

Update the [configuration file](./config/config.toml) by adding your [GitHub Personal Access Token (PAT)]((https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)) to the `github_token` field.
This token is required to query the [GitHub Advisory Database](https://github.com/advisories).

### MacOS

Prerequisites:

- Xcode Command Line Tools (`xcode-select --install`)
- Rust
- CMake (`brew install cmake`)
- vcpkg (https://github.com/Microsoft/vcpkg.git)

Execute the installation script `./install.sh`.

### Linux

Prerequisites:

- build-essential
- cmake
- Rust
- vcpkg

Execute the installation script `./install.sh`.

### Windows

Prerequisites:

- Git (with Git Bash)
- Visual Studio 2022 with C++ workload
- CMake (3.13+)
- Rust toolchain (rustup + cargo)
- LLVM
- vcpkg

Execute the installation script `./install-win.sh`.

> [!NOTE]
> Open Git Bash and run:  
> `VCPKG_ROOT=/path/to/vcpkg ./install-win.sh`  
> e.g. `VCPKG_ROOT=/c/Users/Tom/new-test/vcpkg ./install-win.sh`

## Usage

- Upload SBOM to the system:

```Bash
target/release/zksbom-operator upload_sbom \
--api-key <api-key> \
--sbom </path/to/SBOM>
```

- Trigger dependency vulnerability mapping:

```Bash
target/release/zksbom-operator map_vulnerabilities
```

- Retrieve commitment from the system:

```Bash
target/release/zksbom-operator get_commitment \
--vendor <vendor> \
--product <product> \
--version <version> \
--method <method>
```

- Create proof:

```Bash
target/release/zksbom-operator get_zkp \
--api-key <api-key> \
--method <method> \
--commitment <commitment> \
--check <CVE-or-dependency>
```

or:

```Bash
target/release/zksbom-operator get_zkp_full \
--api-key <api-key> \
--method <method> \
--vendor <vendor> \
--product <product> \
--version <version> \
--check <CVE-or-dependency>
```

Explicit examples can be seen [here](./EXAMPLE_USAGE.md).

## Cryptographic Proofs

- Inclusion Proof
  - Proofs that a vulnerability or dependency is present in the SBOM.
  - Supported by the following methods:
    - Merkle Tree (`merkle-tree`)
    - Sparse Merkle Tree (`sparse-merkle-tree`)
    - Merkle Patricia Trie (`merkle-patricia-trie`)
    - Ordered Zero-Knowledge Set (`ozks`)
- Non-inclusion Proof
  - Proofs that a vulnerability or dependency is absent from the SBOM.
  - Supported by the following methods:
    - Sparse Merkle Tree (`sparse-merkle-tree`)
    - Merkle Patricia Trie (`merkle-patricia-trie`)
    - Ordered Zero-Knowledge Set (`ozks`)
