import os
import csv
import glob
import pandas as pd

def process_entropy_file(filepath):
    """
    Reads a CSV file and computes the average of:
    - Shannon entropy
    - Rényi entropy
    - Tsallis entropy
    - Payload size (data_len)
    - Created by: [Ahmad Usman]
    - Date: [2025-July-29]
    """
    shannon_list = []
    renyi_list = []
    tsallis_list = []
    data_len_list = []

    with open(filepath, 'r') as file:
        reader = csv.reader(file)
        header = next(reader, None)  # skip header if present
        for row in reader:
            try:
                data_len = float(row[7])             # data_len
                shannon = float(row[8])              # entropy_shannon
                renyi = float(row[9])                # entropy_renyi
                tsallis = float(row[10])             # entropy_tsallis

                data_len_list.append(data_len)
                shannon_list.append(shannon)
                renyi_list.append(renyi)
                tsallis_list.append(tsallis)
            except (ValueError, IndexError):
                continue  # Skip malformed rows

    avg_len = sum(data_len_list) / len(data_len_list) if data_len_list else 0
    avg_shannon = sum(shannon_list) / len(shannon_list) if shannon_list else 0
    avg_renyi = sum(renyi_list) / len(renyi_list) if renyi_list else 0
    avg_tsallis = sum(tsallis_list) / len(tsallis_list) if tsallis_list else 0

    return avg_len, avg_shannon, avg_renyi, avg_tsallis

def main(input_folder, output_csv):
    # Check if the input folder exists
    if not os.path.isdir(input_folder):
        raise FileNotFoundError(f"Input folder does not exist: {input_folder}")

    result = []

    for filepath in glob.glob(os.path.join(input_folder, '*.csv')):
        filename = os.path.basename(filepath)
        avg_len, avg_shannon, avg_renyi, avg_tsallis = process_entropy_file(filepath)

        result.append({
            'filename': filename,
            'avg_data_len': avg_len,
            'avg_shannon': avg_shannon,
            'avg_renyi': avg_renyi,
            'avg_tsallis': avg_tsallis
        })

    df = pd.DataFrame(result)
    df.to_csv(output_csv, index=False)
    print(f"Summary written to {output_csv}")

# Example usage
if __name__ == '__main__':
    input_folder = os.path.expanduser('~/update_traffic/dataset/entropy/iot-data/us/roku-tv')
    output_csv = os.path.expanduser('~/update_traffic/dataset/entropy_average/iot-data/us/roku-tv/entropy_summary.csv')

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    main(input_folder, output_csv)
