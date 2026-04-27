# Notes

Run `./run.sh` to trigger the performance meassurement.

To run `run-real-world-sboms.sh`, the dataset of "[Replication Package for Wild SBOMs](https://zenodo.org/records/17397281)" (to be precise the `sbom-files.tar.ztsd`) must be available in a folder called `sbom-files` (after running `tar --zstd -xvf sbom-files.tar.ztsd`).

The SBOM `CVE-2021-44228.cdx.json` is a special SBOM used to stress test `zksbom`. It is an SBOM containing 10,000 components of which 73 are vulnerable to CVE-2021-44228.
