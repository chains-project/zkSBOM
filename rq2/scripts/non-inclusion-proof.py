import requests
import subprocess
import time
import os
import platform

# --- Configuration ---
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000        # Max 2000
LAST_N_ENTRIES = 5000          # Change this to process a different tail size
DELAY_SECONDS = 8              # Increased delay for safety without API key
PROOF_PATH = "./tmp/output/proof.txt"

def process_cves(commitment: str):
    # --- Preflight: find the current total so we can anchor the start index ---
    print("Fetching total CVE count from NVD...")
    try:
        preflight = requests.get(BASE_URL, params={"resultsPerPage": 1, "startIndex": 0}, timeout=30)
        preflight.raise_for_status()
        total_results = preflight.json().get("totalResults", 0)
    except requests.exceptions.RequestException as e:
        print(f"Could not fetch total results: {e}")
        return

    start_index = max(0, total_results - LAST_N_ENTRIES)
    upper_limit = total_results   # process until the end of the dataset
    total_processed = 0
    failed = 0
    skipped = 0

    print(f"Total CVEs in NVD: {total_results}")
    print(f"Starting at index {start_index} (last {LAST_N_ENTRIES} entries)\n")

    while total_processed < LAST_N_ENTRIES:
        print(f"\n--- Fetching page starting at index {start_index} ---")

        params = {
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }

        try:
            response = requests.get(BASE_URL, params=params, timeout=30)

            if response.status_code in (403, 503):
                print("Rate limit exceeded! Sleeping for 30 seconds before retry...")
                time.sleep(30)
                continue

            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("No more data found.")
                break

            for item in vulnerabilities:
                if total_processed >= LAST_N_ENTRIES:
                    break

                total_processed += 1
                cve_id = item["cve"]["id"]
                print(f"[{total_processed}/{LAST_N_ENTRIES}] Processing {cve_id}...")

                # Run zkSBOM tool
                os.chdir('../zksbom-operator')
                try:
                    cmd = [
                        "target/release/zksbom-operator",
                        "create_proof",
                        "--api-key", "123",
                        "--method", "ozks",
                        "--commitment", commitment,
                        "--check", cve_id,
                        "--timing_analysis", "true",
                        "--timing_analysis_output", "../rq2/results/non-inclusion/create-proof.csv"
                    ]
                    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
                    if "panicked" in result.stdout or "panicked" in result.stderr:
                        print("\tRun failed (operator): ... skip")
                        failed += 1
                        continue
                except Exception as e:
                    print(f"\tRun failed (operator): {e}")
                    failed += 1
                    continue

                count = get_proofed_component_count(PROOF_PATH)
                if count == 0:
                    print("\tProof was computed for 0 components... skip")
                    remove_last_line("../rq2/results/non-inclusion/create-proof.csv")
                    skipped += 1
                    continue
                append_to_csv("../rq2/results/non-inclusion/create-proof.csv", count)
                append_to_csv("../rq2/results/non-inclusion/create-proof.csv", cve_id)

                size = os.path.getsize(PROOF_PATH)
                write_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", "ozks")
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", size)
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", count)
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", cve_id)

                os.chdir('../zksbom-verifier')
                try:
                    cmd = [
                        "target/release/zksbom-verifier",
                        "verify",
                        "--method", "ozks",
                        "--commitment", commitment,
                        "--proof_path", f"../zksbom-operator/{PROOF_PATH}",
                        "--timing_analysis", "true",
                        "--timing_analysis_output", "../rq2/results/non-inclusion/verify-proof.csv"
                    ]
                    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
                except Exception as e:
                    print(f"\tRun failed (verifier): {e}")
                    failed += 1

                append_to_csv("../rq2/results/non-inclusion/verify-proof.csv", count)
                append_to_csv("../rq2/results/non-inclusion/verify-proof.csv", cve_id)

            os.chdir('../zksbom-operator')
            start_index += RESULTS_PER_PAGE

            if start_index >= total_results:
                print("\nReached the end of the entire NVD database.")
                break

            print(f"\nPage complete. Waiting {DELAY_SECONDS}s to avoid rate limits...")
            time.sleep(DELAY_SECONDS)

        except requests.exceptions.RequestException as e:
            print(f"\nAn error occurred: {e}")
            print("Retrying in 10 seconds...")
            time.sleep(10)

    print(f"\nDone. Processed {total_processed} CVEs total.")
    print(f"Failed CVEs: {failed}")
    print(f"Skipped CVEs: {skipped}")


def remove_last_line(csv_path: str):
    try:
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            return

        with open(csv_path, 'rb+') as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell() - 1

            while pos > 0:
                f.seek(pos)
                if f.read(1) not in b'\n\r':
                    break
                pos -= 1

            while pos > 0:
                f.seek(pos)
                if f.read(1) in b'\n\r':
                    f.seek(pos + 1)
                    f.truncate()
                    return
                pos -= 1

            if pos == 0:
                f.seek(0)
                f.truncate()

    except Exception as e:
        print(f"Failed to remove last line: {e}")


def append_to_csv(csv_path: str, count: int):
    try:
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            return

        with open(csv_path, 'rb+') as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell() - 1
            while pos > 0:
                f.seek(pos)
                char = f.read(1)
                if char != b'\n' and char != b'\r':
                    f.seek(pos + 1)
                    f.truncate()
                    break
                pos -= 1
            f.write(f",{count}\n".encode('utf-8'))

    except Exception as e:
        print(f"Failed to update CSV: {e}")


def write_to_csv(csv_path: str, count: int):
    try:
        if not os.path.exists(csv_path):
            return

        with open(csv_path, 'rb+') as f:
            f.seek(0, os.SEEK_END)
            f.write(f"{count}\n".encode('utf-8'))

    except Exception as e:
        print(f"Failed to update CSV: {e}")


def get_proofed_component_count(proof_path: str) -> int:
    try:
        if not os.path.exists(proof_path) or os.path.getsize(proof_path) == 0:
            return 0

        with open(proof_path, 'r') as f:
            line_count = sum(1 for line in f if line.strip())

        return line_count // 3

    except Exception as e:
        print(f"Error reading proof file: {e}")
        return 0


def upload_sbom():
    cmd = [
        "target/release/zksbom-operator",
        "upload_sbom",
        "--api-key", "123",
        "--sbom", "../rq2/scripts/1000.cdx.json"
    ]
    subprocess.run(cmd, check=False, capture_output=True)


def get_commitment():
    cmd = [
        "target/release/zksbom-operator",
        "get_commitment",
        "--method", "ozks",
        "--vendor", "RQ2",
        "--product", "1000",
        "--version", "0.1.0",
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout:
        return result.stdout.split("Commitment:")[-1].strip()
    return None


if __name__ == "__main__":
    for x in range(5):
        print("-----")
        print(f"--- Iteration {x+1}:")
        print("-----")
        upload_sbom()
        commitment = get_commitment()
        print(f"Commitment: `{commitment}`")
        process_cves(commitment)