#!/usr/bin/env python3

import os
import json
import pickle
import argparse
import time
from collections import Counter, defaultdict

# Track execution time
start_time = time.perf_counter()

# Constants
PICKLE_FILE_CONST = "file_metadata.pickle"
ANAL_RESULTS_CONST = "bin_results.json"
UPDATE_KEYS = ["update", "firmware", "software", "download"]

# Parse arguments
parser = argparse.ArgumentParser(description='Check devices with update-related flags set to true')
parser.add_argument('input_dir', type=str, help='Input directory containing JSON and pickle files')
args = parser.parse_args()

# Load analysis results
with open(os.path.join(args.input_dir, ANAL_RESULTS_CONST), 'r') as f:
    results_data = json.load(f)
    print("[+] Loaded analysis JSON")

# Load device metadata
with open(os.path.join(args.input_dir, PICKLE_FILE_CONST), 'rb') as f:
    device_metadata = pickle.load(f)
    print("[+] Loaded device metadata")

# Helper to get device by UUID
def get_device_by_uuid(uuid):
    for device in device_metadata:
        if device['uuid'] == uuid:
            return device
    return None

# Counters
true_counter = Counter()
device_counter = Counter()
keyword_per_device = defaultdict(Counter)  # NEW: device -> keyword -> count

# Search for relevant entries
print("\nDevices with at least one update-related flag set to true:\n")

for entry in results_data.get("results", []):
    uuid = entry.get("uuid")
    device_info = get_device_by_uuid(uuid)
    if not device_info:
        continue

    device_name = device_info.get("device")
    for file_info in entry.get("file_infos", []):
        update_meta = file_info.get("update_meta", {})
        found_true = False

        for key in UPDATE_KEYS:
            if update_meta.get(key) is True:
                true_counter[key] += 1
                keyword_per_device[device_name][key] += 1  # NEW
                found_true = True

        if found_true:
            device_counter[device_name] += 1
            print(f"Device: {device_name}")
            print(f"UUID: {uuid}")
            print(f"File: {file_info.get('filename')}")
            print("Update Meta:", update_meta)
            print("-" * 60)

# Print summary counts
print("\n=== Summary of TRUE keyword occurrences ===")
for key in UPDATE_KEYS:
    print(f"{key}: {true_counter[key]}")

print("\n=== Device occurrence summary ===")
for device, count in device_counter.most_common():
    print(f"{device}: {count}")

# Print keyword summary per device (skipping 0s)
print("\n=== Per-device keyword TRUE count (non-zero only) ===")
for device, key_counts in keyword_per_device.items():
    nonzero_keys = {k: v for k, v in key_counts.items() if v > 0}
    if nonzero_keys:
        print(f"\nDevice: {device}")
        for key, count in nonzero_keys.items():
            print(f"  {key}: {count}")


# Print execution time
end_time = time.perf_counter()
print(f"\n[+] Script finished in {end_time - start_time:.2f} seconds")
