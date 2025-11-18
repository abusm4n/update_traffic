import csv
import subprocess
from collections import defaultdict

# --- CONFIG ---
pcap_file = "./controlled/dataset/tapo/tapo.pcapng"
output_csv = "./controlled/stream/tapo_stream_sizes.csv"
include_megabytes = True   # set False if you do not want MB column

# --- RUN TSHARK ---
cmd = [
    "tshark",
    "-r", pcap_file,
    "-T", "fields",
    "-e", "tcp.stream",
    "-e", "frame.len"
]

print("Running tshark...")

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

stream_bytes = defaultdict(int)

# --- PARSE OUTPUT ---
for line in process.stdout:
    parts = line.strip().split()
    if len(parts) != 2:
        continue

    stream, frame_len = parts

    if stream == "" or frame_len == "":
        continue

    try:
        stream = int(stream)
        frame_len = int(frame_len)
    except ValueError:
        continue

    stream_bytes[stream] += frame_len

# remove zero-byte streams
stream_bytes = {s: b for s, b in stream_bytes.items() if b > 0}

# --- WRITE CSV ---
print(f"Writing CSV: {output_csv}")

with open(output_csv, "w", newline="") as f:
    writer = csv.writer(f)
    
    if include_megabytes:
        writer.writerow(["stream", "bytes", "megabytes"])
        for s, b in sorted(stream_bytes.items()):
            writer.writerow([s, b, round(b / 1048576, 3)])
    else:
        writer.writerow(["stream", "bytes"])
        for s, b in sorted(stream_bytes.items()):
            writer.writerow([s, b])

print("Done.")
