import os

# Methods and component counts
methods = [
    "merkle-patricia-trie",
    "merkle-tree",
    "sparse-merkle-tree",
    "ozks"
]

counts = [2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024]

results = {}

for method in methods:
    result_list = []
    folder = f"../zksbom/tmp/timing_analysis/generate_proof/proofs_{method}/"

    for count in counts:
        filename = f"proof_{count}_{method}.txt"
        filepath = os.path.join(folder, filename)

        if os.path.isfile(filepath):
            size = os.path.getsize(filepath)
            result_list.append((count, size))
        else:
            print(f"Warning: File not found: {filepath}")

    results[method] = result_list

# Print the output
for method in methods:
    values = results.get(method, [])
    formatted = " ".join(f"({count}, {size})" for count, size in values)
    print(f"{method}: {formatted}")
