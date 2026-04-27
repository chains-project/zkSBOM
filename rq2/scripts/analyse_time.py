import csv
import sys
from collections import defaultdict
from statistics import median

def analyze(filepath):
    data = defaultdict(list)
    with open(filepath, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) == 4:
                row = row[:3]
            if len(row) != 3:
                continue
            method, time_str, dep_str = row
            method = method.strip()
            try:
                time = float(time_str.strip())
                dep = int(dep_str.strip())
            except ValueError:
                continue
            data[(method, dep)].append(time)

    sorted_data = sorted(data.items(), key=lambda x: (x[0][0], x[0][1]))

    print(f"{'Method':<10} {'Dep Count':>10} {'Median Time':>15} {'Samples':>8}")
    print("-" * 48)
    for (method, dep), times in sorted_data:
        med = median(times)
        print(f"{method:<10} {dep:>10} {med:>15.9f} {len(times):>8}")

    by_method = defaultdict(list)
    for (method, dep), times in sorted_data:
        med = median(times)
        by_method[method].append((dep, med))

    for method, points in sorted(by_method.items()):
        print(f"% {method}")
        coords = " ".join(f"({dep},{med:.9f})" for dep, med in points)
        print(f"\\{{{coords}}}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "data.csv"
    analyze(filepath)