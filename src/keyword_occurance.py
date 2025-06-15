#!/usr/bin/env python3

import os
import csv
import argparse
from pathlib import Path
from joblib import Parallel, delayed
import pyshark
from tqdm import tqdm
from multiprocessing import Manager

# Define keywords
KEYWORDS = ['update', 'upgrade', 'firmware', 'software', 'download']

# Parse arguments
parser = argparse.ArgumentParser(description='Search PCAPs for update-related keywords')
parser.add_argument('input_dir', type=str, help='Directory of .pcap files to scan recursively')
parser.add_argument('output_csv', type=str, help='Path to output CSV file with matches')
args = parser.parse_args()

input_dir = Path(args.input_dir).resolve()
output_csv = Path(args.output_csv).resolve()
pcap_files = list(input_dir.rglob('*.pcap'))
total_files = len(pcap_files)

print(f"[+] Found {total_files} .pcap files to scan.")

def search_keywords_in_pcap(filepath):
    try:
        cap = pyshark.FileCapture(str(filepath), use_json=True, include_raw=True, decode_as={}, keep_packets=False)
        for packet in cap:
            packet_str = str(packet).lower()
            if any(keyword in packet_str for keyword in KEYWORDS):
                cap.close()
                return str(filepath)
        cap.close()
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
    return None

def worker(file_path, progress_queue):
    result = search_keywords_in_pcap(file_path)
    progress_queue.put(1)  # Notify progress
    return result

# Use Manager for progress queue
with Manager() as manager:
    progress_queue = manager.Queue()

    # Start tqdm listener
    from threading import Thread

    def progress_listener(total, queue):
        with tqdm(total=total, desc="Scanning PCAPs", unit="file") as pbar:
            for _ in range(total):
                queue.get()
                pbar.update(1)

    progress_thread = Thread(target=progress_listener, args=(total_files, progress_queue))
    progress_thread.start()

    # Parallel execution
    results = Parallel(n_jobs=5)(
        delayed(worker)(f, progress_queue) for f in pcap_files
    )

    progress_thread.join()

# Filter results
matches = [r for r in results if r]

# Save to CSV
output_csv.parent.mkdir(parents=True, exist_ok=True)
with open(output_csv, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['matched_pcap'])
    for match in matches:
        writer.writerow([match])

print(f"[+] Found {len(matches)} matching .pcap files.")
print(f"[+] Matches saved to: {output_csv}")
