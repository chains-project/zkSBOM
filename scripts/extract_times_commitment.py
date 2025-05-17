import re
from collections import defaultdict

filename = "../zksbom/tmp/timing_analysis/upload_sbom.txt"

# Store the results by method
results = defaultdict(list)

# Read the file content
with open(filename, 'r') as f:
    content = f.read()

# Extract all blocks using regex
blocks = re.findall(r"### (\d+) components,.*?###|\Z", content + "\n###", re.DOTALL)
blocks_data = re.split(r"### \d+ components,.*?###", content)[1:]

# Parse each block
for block, block_data in zip(blocks, blocks_data):
    component_count = int(block)
    for line in block_data.strip().splitlines():
        match = re.match(r"Method: (.*), Elapsed: ([0-9.eE+-]+) seconds", line.strip())
        if match:
            method = match.group(1)
            time = float(match.group(2))
            results[method].append((component_count, time))

# Print the formatted output
for method, values in results.items():
    formatted = " ".join(f"({comp}, {format(time, '.5f')})" for comp, time in values)
    print(f"{method}: {formatted}")

