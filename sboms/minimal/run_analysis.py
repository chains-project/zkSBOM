#!/usr/bin/env python3
import subprocess
import os
import re

def write_count_header(output_file: str, count: int, method: str) -> None:
    with open(output_file, 'a') as f:
        f.write(f"\n### {count} components, method: {method} ###\n")

def run_and_log(cmd: str, output_file: str) -> None:
    # Run command and capture output
    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Write output to file
    with open(output_file, 'a') as f:
        if result.stdout:
            f.write(result.stdout)
        if result.stderr:
            f.write(result.stderr)

def get_all_commitments(commitment_file: str, method: str) -> list[tuple[int, str]]:
    commitments = []
    try:
        with open(commitment_file, 'r') as f:
            content = f.read()
            # Find all sections with commitments
            sections = re.finditer(r"### (\d+) components.*?Commitment: (0x[a-fA-F0-9]+)", content, re.DOTALL)
            for section in sections:
                count = int(section.group(1))
                commitment = section.group(2)
                commitments.append((count, commitment))
    except FileNotFoundError:
        print(f"Warning: Could not find commitment file {commitment_file}")
    return sorted(commitments, key=lambda x: x[0])  # Sort by count

def main(command: str) -> None:
    # Define the methods and component counts
    methods = [
        'merkle-tree',
        'sparse-merkle-tree',
        'merkle-patricia-trie'
    ]

    component_counts = [
        # 1,
        2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024
    ]

    
    if command == "upload_sbom":
        for count in component_counts:
            output_file = f"./tmp/timing_analysis/upload_sbom.txt"
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            write_count_header(output_file, count, command)
            print(f"\nRunning upload_sbom for {count} components...")
            cmd = f"./target/release/zksbom upload_sbom --api-key 123 --sbom ../sboms/minimal/{count}_components.json --timing_analysis_output '{output_file}' --timing_analysis true"
            subprocess.run(cmd, shell=True, check=True)
        
    elif command == "get_commitment":
        for method in methods:
            for count in component_counts:
                output_file = f"./tmp/timing_analysis/get_commitment/get_commitment_{method}.txt"
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                write_count_header(output_file, count, command)
                print(f"\nRunning get_commitment for {count} components with {method}...")
                cmd = f"./target/release/zksbom get_commitment --vendor 'Tom Sorger <sorger@kth.se>' --product '{count}_components' --version '0.1.0' --method '{method}' --timing_analysis_output '{output_file}' --timing_analysis true"
                run_and_log(cmd, output_file)
        
    elif command == "generate_proof":
        for method in methods:
            # Get all commitments for this method
            commitment_file = f"./tmp/timing_analysis/get_commitment/get_commitment_{method}.txt"
            commitments = get_all_commitments(commitment_file, method)
            if not commitments:
                print(f"Error: No commitments found for method {method}")
                continue

            for count, commitment in commitments:
                output_file = f"./tmp/timing_analysis/generate_proof/generate_proof_{method}.txt"
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                write_count_header(output_file, count, command)
                print(f"\nRunning generate_proof for {count} components with {method}...")
                print(f"Using commitment: {commitment}")
                test_output = f"./tmp/timing_analysis/generate_proof/proofs_{method}/proof_{count}_{method}.txt"

                cmd = f"./target/release/zksbom get_zkp --api-key 123 --method '{method}' --commitment '{commitment}' --vulnerability 'CVE-2025-24898' --timing_analysis_output '{output_file}' --output {test_output} --timing_analysis true"
                subprocess.run(cmd, shell=True, check=True)
            
    elif command == "verify_proof":
        for method in methods:
            # Get all commitments for this method
            commitment_file = f"../zksbom/tmp/timing_analysis/get_commitment/get_commitment_{method}.txt"
            commitments = get_all_commitments(commitment_file, method)
            if not commitments:
                print(f"Error: No commitments found for method {method}")
                continue

            for count, commitment in commitments:
                output_file = f"../zksbom/tmp/timing_analysis/verify_proof/verify_proof_{method}.txt"
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                write_count_header(output_file, count, command)
                print(f"\nRunning verify_proof for {count} components with {method}...")
                print(f"Using commitment: {commitment}")
                cmd = f"./target/release/zksbom-verifier verify --method '{method}' --commitment '{commitment}' --proof_path '../zksbom/tmp/timing_analysis/generate_proof/proofs_{method}/proof_{count}_{method}.txt' --timing_analysis_output '{output_file}' --timing_analysis true"
                subprocess.run(cmd, shell=True, check=True)
        
    else:
        raise ValueError(f"Invalid command: {command}")

    print("\nAnalysis has been run successfully!")

if __name__ == "__main__":
    # zksbom
    # command = "upload_sbom"
    # command = "get_commitment"
    # command = "generate_proof"
    
    # zksbom-verifier
    command = "verify_proof"

    main(command)
