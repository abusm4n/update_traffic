#!/bin/bash
# Script to process pcap files and compute entropy metrics

input_folder="${HOME}/update_traffic/dataset/update_dataset/iot-data/uk-vpn"
output_folder="${HOME}/update_traffic/dataset/renyi/iot-data/uk-vpn"

find "$input_folder" -type f -name '*.pcap' | while read -r pcapfile; do
  # Extract the relative path of the pcap file from the input_folder
  relpath=$(realpath --relative-to="$input_folder" "$pcapfile")

  # Extract the device name (first folder after input_folder)
  device_name=$(echo "$relpath" | cut -d'/' -f1)

  # Create output subfolder for the device
  device_output_folder="$output_folder/$device_name"
  mkdir -p "$device_output_folder"

  # Extract the base filename
  base=$(basename "$pcapfile" .pcap)
  jsonfile="$device_output_folder/${base}.json"
  csvfile="$device_output_folder/${base}.csv"

  echo "Processing $pcapfile ..."
  ../intl-iot/encryption/encryption.sh "$pcapfile" "$csvfile" "$jsonfile"
done
