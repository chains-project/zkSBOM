import csv
import sys
from collections import defaultdict

def analyze(filepath):
    data = defaultdict(list)

    with open(filepath, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != 3:
                continue
            method, time_str, dep_str = row
            method = method.strip()
            try:
                time = float(time_str.strip())
                dep = int(dep_str.strip())  # strips leading zeros
            except ValueError:
                continue
            data[(method, dep)].append(time)

    # Print results sorted by method, then dependency count
    print(f"{'Method':<10} {'Dep Count':>10} {'Avg Time':>15} {'Samples':>8}")
    print("-" * 48)
    for (method, dep), times in sorted(data.items(), key=lambda x: (x[0][0], x[0][1])):
        avg = sum(times) / len(times)
        print(f"{method:<10} {dep:>10} {avg:>15.9f} {len(times):>8}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "data.csv"
    analyze(filepath)

    