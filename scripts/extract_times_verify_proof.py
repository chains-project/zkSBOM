import re
from collections import defaultdict

# Methods and corresponding filenames
methods = [
    "merkle-patricia-trie",
    "merkle-tree",
    "sparse-merkle-tree"
]

results = defaultdict(list)

# Loop through each file
for method in methods:
    filename = f"../zksbom/tmp/timing_analysis/verify_proof/verify_proof_{method}.txt"
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Warning: File {filename} not found. Skipping.")
        continue

    # Extract all blocks
    blocks = re.findall(r"### (\d+) components,.*?###|\Z", content + "\n###", re.DOTALL)
    blocks_data = re.split(r"### \d+ components,.*?###", content)[1:]

    # Parse each block
    for block, block_data in zip(blocks, blocks_data):
        component_count = int(block)
        match = re.search(rf"Method: {re.escape(method)}, Elapsed: ([0-9.eE+-]+) seconds", block_data)
        if match:
            time = float(match.group(1))
            results[method].append((component_count, time))

# Print formatted output
for method in methods:
    values = results[method]
    formatted = " ".join(f"({comp}, {format(time, '.5f')})" for comp, time in values)
    print(f"{method}: {formatted}")
