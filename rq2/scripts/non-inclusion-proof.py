import requests
import subprocess
import time
import os
import platform

# --- Configuration ---
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000        # Max 2000
UPPER_LIMIT = 345786           # Adjust this to your desired limit
DELAY_SECONDS = 8              # Increased delay for safety without API key
PROOF_PATH = "./tmp/output/proof.txt"

def process_cves(commitment: str):
    start_index = 345760 # Last 5,000 entries
    total_processed = 0
    failed = 0
    skipped = 0
    
    while total_processed  < UPPER_LIMIT:
        print(f"\n--- Fetching page starting at index {start_index} ---")
        
        params = {
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }

        try:
            # No API Key header needed here
            response = requests.get(BASE_URL, params=params, timeout=30)
            
            # If the NVD blocks you temporarily, this will catch the 403 or 503 error
            if response.status_code == 403 or response.status_code == 503:
                print("Rate limit exceeded! Sleeping for 30 seconds before retry...")
                time.sleep(30)
                continue

            response.raise_for_status()
            data = response.json()
            
            # Get the list of vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("No more data found.")
                break

            # Loop through each CVE in the current batch
            for item in vulnerabilities:
                if total_processed >= UPPER_LIMIT:
                    break
                
                total_processed += 1
                cve_id = item["cve"]["id"]
                print(f"[{total_processed}] Processing {cve_id}...")
                
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
                
                # Check proof file lines.
                count = get_proofed_component_count(PROOF_PATH)
                if count == 0:
                    print("\tProof was computed for 0 components... skip")
                    remove_last_line("../rq2/results/non-inclusion/create-proof.csv")
                    skipped += 1
                    continue
                append_to_csv("../rq2/results/non-inclusion/create-proof.csv", count)
                append_to_csv("../rq2/results/non-inclusion/create-proof.csv", cve_id)


                # Get Proof File Size
                size = os.path.getsize(PROOF_PATH)

                write_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", "ozks")
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", size)
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", count)
                append_to_csv("../rq2/results/non-inclusion/non-inclusion-proof-file-size.csv", cve_id)


                # Verify Proof
                os.chdir('../zksbom-verifier')
                try:
                    cmd = [
                        "target/release/zksbom-verifier", 
                        "verify",
                        "--method", "ozks",
                        "--commitment", commitment,
                        "--proof_path", PROOF_PATH,
                        "--timing_analysis", "true",
                        "--timing_analysis_output", "../rq2/results/non-inclusion/verify-proof.csv"
                    ]
                    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
                except Exception as e:
                    print(f"\tRun failed (verifier): : {e}")
                    failed += 1

                append_to_csv("../rq2/results/non-inclusion/verify-proof.csv", count)
                append_to_csv("../rq2/results/non-inclusion/verify-proof.csv", cve_id)

            os.chdir('../zksbom-operator')
            # Prepare for next page
            total_results = data.get("totalResults", 0)
            start_index += RESULTS_PER_PAGE
            
            if start_index >= total_results:
                print("\nReached the end of the entire NVD database.")
                break

            # Mandatory wait to stay within public rate limits
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
            # 1. Move to the very end
            f.seek(0, os.SEEK_END)
            pos = f.tell() - 1

            # 2. Skip any trailing newlines at the very end of the file
            while pos > 0:
                f.seek(pos)
                if f.read(1) not in b'\n\r':
                    break
                pos -= 1

            # 3. Now back up until we find the NEXT newline (the start of the last line)
            while pos > 0:
                f.seek(pos)
                if f.read(1) in b'\n\r':
                    # Found the newline that ends the second-to-last line
                    f.seek(pos + 1) 
                    f.truncate()
                    return # Done
                pos -= 1
            
            # 4. If we reached the start of the file (pos == 0), just clear the whole file
            if pos == 0:
                f.seek(0)
                f.truncate()

    except Exception as e:
        print(f"Failed to remove last line: {e}")


def append_to_csv(csv_path: str, count: int):
    try:
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            return

        # Open in 'read/write' mode
        with open(csv_path, 'rb+') as f:
            # Move to the very end of the file
            f.seek(0, os.SEEK_END)
            
            # Back up until we find the last non-newline character
            pos = f.tell() - 1
            while pos > 0:
                f.seek(pos)
                char = f.read(1)
                if char != b'\n' and char != b'\r':
                    # We found the end of the actual text
                    # Set the file size to this position (removing the trailing newline)
                    f.seek(pos + 1)
                    f.truncate()
                    break
                pos -= 1
            
            # Now we are at the end of the text line, add our data and a NEW newline
            f.write(f",{count}\n".encode('utf-8'))
            
    except Exception as e:
        print(f"Failed to update CSV: {e}")

def write_to_csv(csv_path: str, count: int):
    try:
        if not os.path.exists(csv_path):
            return

        # Open in 'read/write' mode
        with open(csv_path, 'rb+') as f:
            # Move to the very end of the file
            f.seek(0, os.SEEK_END)
            
            # Now we are at the end of the text line, add our data and a NEW newline
            f.write(f"{count}\n".encode('utf-8'))
            
    except Exception as e:
        print(f"Failed to update CSV: {e}")

def get_proofed_component_count(proof_path: str) -> int:
    try:
        # Check if file exists and isn't empty
        if not os.path.exists(proof_path) or os.path.getsize(proof_path) == 0:
            return 0
            
        with open(proof_path, 'r') as f:
            # count lines (ignoring empty lines if necessary)
            line_count = sum(1 for line in f if line.strip())
            
        # Perform the calculation (integer division)
        num_components = line_count // 3
        return num_components

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
    res = subprocess.run(cmd, check=False, capture_output=True)


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
        output = result.stdout.split("Commitment:")[-1].strip()
        return output
    
    return None


if __name__ == "__main__":
    upload_sbom()
    commitment = get_commitment()
    print(f"Commitment: `{commitment}`")
    process_cves(commitment)