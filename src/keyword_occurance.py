#!/usr/bin/env python3

import os
import argparse
import pickle
import json
from collections import defaultdict
import matplotlib.pyplot as plt
import pandas as pd

parser = argparse.ArgumentParser(description='Keyword Occurrence Chart by Device')

PICKLE_FILE_CONST = "file_metadata.pickle"
ANAL_RESULTS_CONST = "bin_results.json"

parser.add_argument('input', type=str, help='Input dir')
parser.add_argument('output', type=str, help='Output dir')

args = parser.parse_args()
input_dir = args.input
output_dir = args.output

# Load JSON analysis results
with open(os.path.join(input_dir, ANAL_RESULTS_CONST), 'r') as f:
    data = json.load(f)
    print("[+] Loaded packet JSON")

# Load device metadata (pickle)
with open(os.path.join(input_dir, PICKLE_FILE_CONST), 'rb') as f:
    device_metadata = pickle.load(f)
    print("[+] Loaded metadata pickle")

# Helper to look up device info by UUID
def get_device_by_uuid(uuid):
    for device in device_metadata:
        if device['uuid'] == uuid:
            return device 
    return None

# Define keywords to look for
keywords = ['tls', 'firmware', 'encrypted', 'update', 'patch', 'ota']

# Track keyword counts per device
keyword_device_counter = defaultdict(lambda: defaultdict(int))

# Iterate through analysis results
for device_result in data['results']:
    uuid = device_result['uuid']
    device_info = get_device_by_uuid(uuid)
    if not device_info:
        continue
    device_name = device_info['device']

    file_infos = device_result.get('file_infos', [])
    for file_info in file_infos:
        update_meta = file_info.get('update_meta', {})
        for key in update_meta.keys():
            key_lower = key.lower()
            for keyword in keywords:
                if keyword in key_lower:
                    keyword_device_counter[device_name][keyword] += 1

# Convert to DataFrame
df = pd.DataFrame(keyword_device_counter).fillna(0).astype(int).T  # Devices as rows

# Remove devices with no keyword occurrences
df = df[df.sum(axis=1) > 0]

# Plot if there's data
if df.empty:
    print("[-] No keyword occurrences found for any device. No chart generated.")
else:
    ax = df.plot(kind='barh', stacked=True, figsize=(12, 8))
    ax.set_title('Keyword Occurrence by Device')
    ax.set_xlabel('Keyword Occurrences')
    ax.set_ylabel('Device')
    plt.tight_layout()

    # Save plot
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'keyword_occurrence_by_device.png')
    plt.savefig(out_path)
    print(f"[+] Saved chart to {out_path}")
