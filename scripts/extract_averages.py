import re
from collections import defaultdict

# filename = "../sboms/minimal/size_proof_file.txt"
# filename = "../sboms/minimal/timing_generate_commitment.txt"
# filename = "../sboms/minimal/timing_generate_proof.txt"
filename = "../sboms/minimal/timing_verify_proof.txt"

# Structure to hold parsed data
aggregate = defaultdict(lambda: defaultdict(list))

# Read and parse the file
with open(filename, "r") as f:
    for line in f:
        match = re.match(r"^(.*?):\s+(.*)", line.strip())
        if not match:
            continue
        method = match.group(1).strip()
        pairs = re.findall(r"\((\d+),\s*([\d.]+)\)", match.group(2))
        for count_str, value_str in pairs:
            count = int(count_str)
            value = float(value_str)
            aggregate[method][count].append(value)

# Compute and print the averages
for method in sorted(aggregate.keys()):
    averaged = []
    for count in sorted(aggregate[method].keys()):
        values = aggregate[method][count]
        avg = sum(values) / len(values)
        averaged.append(f"({count}, {avg:.6f})")
    print(f"{method}: {' '.join(averaged)}")
