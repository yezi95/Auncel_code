import argparse
import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description="Sample and normalize an XBlock CSV.")
parser.add_argument("input", type=Path, help="source XBlock CSV")
parser.add_argument("--output", type=Path, default=ROOT / "data" / "data.csv")
parser.add_argument("--count", type=int, default=100000)
parser.add_argument("--seed", type=int, default=42)
args = parser.parse_args()
INPUT = args.input if args.input.is_absolute() else ROOT / args.input
OUTPUT = args.output if args.output.is_absolute() else ROOT / args.output
N = args.count
SEED = args.seed

random.seed(SEED)
sample = []
valid_count = 0

with open(INPUT, "r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        sender = row.get("from")
        receiver = row.get("to")

      
        if (
            not sender
            or not receiver
            or sender == "None"
            or receiver == "None"
        ):
            continue

        item = {
            "tx_id": row["transactionHash"],
            "block_number": row["blockNumber"],
            "timestamp": row["timestamp"],
            "sender": sender,
            "receiver": receiver,
            "value": row["value"],
        }

        valid_count += 1

    
        if len(sample) < N:
            sample.append(item)
        else:
            j = random.randrange(valid_count)
            if j < N:
                sample[j] = item


OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT, "w", encoding="utf-8", newline="") as f:
    fields = [
        "tx_id",
        "block_number",
        "timestamp",
        "sender",
        "receiver",
        "value",
    ]

    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(sample)

print("===================================")
print("XBlock sampling completed")
print("===================================")
print("Input:", INPUT)
print("Valid transactions:", valid_count)
print("Sampled transactions:", len(sample))
print("Random seed:", SEED)
print("Output:", OUTPUT)
