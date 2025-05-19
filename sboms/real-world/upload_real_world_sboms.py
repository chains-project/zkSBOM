import os
import subprocess

# Get all files from the directory
sbom_dir = "../sboms/real-world/sboms-fixed"
for index, file_name in enumerate(os.listdir(sbom_dir)):
    # Skip any hidden files or directories
    if file_name.startswith('.'):
        continue
        
    print(f"Processing {file_name} (index {index})...")
    cmd = f"./target/release/zksbom upload_sbom --api-key 123 --sbom ../sboms/real-world/sboms-fixed/{file_name}"
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"Successfully processed {file_name} (index {index})")
    except subprocess.CalledProcessError as e:
        print(f"Error processing {file_name} (index {index}): {e}")
