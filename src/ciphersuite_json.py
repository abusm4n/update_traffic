import json
import sys
import os

# Classification based on known TLS cipher suites (TLS 1.2 mainly)
# Source: IANA TLS Parameters Registry

# Expand the SECURE set with the previously unknown codes (TLS 1.2 ECDHE / AEAD / ChaCha20 suites)
SECURE = {
    '1301', '1302', '1303',  # TLS 1.3
    'c02f', 'c02b', 'c030', 'c02c', 'cca9', 'cca8', 'ccaa', '009f', '009e',
    'c031', 'c032', 'c034', 'c035', 'c036', 'c037',
    'c038', 'c072', 'c073', 'c074', 'c075', 'c076',
    'c077', 'c078', 'c079', 'c07a', 'c07b', 'c07c',
    'c07d', 'c086', 'c087', 'c088', 'c089', 'c08a',
    'c08b', 'c08c', 'c08d', 'c08e', 'c08f', 'c090',
    'c091', 'c092', 'c093', 'c094', 'c095', 'c096',
    'c097', 'c098', 'c099', 'c09a', 'c09b', 'c09c',
    'c09d', 'c09e', 'c09f', 'c0a0', 'c0a1', 'c0a2',
    'c0a3', 'c0a4', 'c0a5', 'c0a6', 'c0a7', 'c0a8',
    'c0a9', 'c0aa', 'c0ab', 'c0ac', 'c0ad', 'c0ae',
    'c0af',
}

RECOMMENDED = {
    '009f', '009e',
    'c023', 'c027', 'c00a', 'c014', 'c009', 'c013',
}

WEAK = {
    '002f', '0033', '0035', '0039', '003c', '003d', '009c', '009d',
}

INSECURE = {
    '0000', '00ff',
}

# Optional: Map cipher codes to human-readable names (add as needed)
CIPHER_NAMES = {
    'c032': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'c031': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'c034': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
    # ... (extend for other codes)
}

def classify_cipher_suite(hexcode: str) -> str:
    h = hexcode.lower().lstrip('0x').zfill(4)
    if h in SECURE:
        return 'Secure'
    elif h in RECOMMENDED:
        return 'Recommended'
    elif h in WEAK:
        return 'Weak'
    elif h in INSECURE:
        return 'Insecure/Other'
    else:
        return 'Unknown'

def process_file(filename, ciphers_found):
    with open(filename, 'r') as f:
        for line in f:
            try:
                packet = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            tls = packet.get('layers', {}).get('tls', {})
            cipher_list = []

            if isinstance(tls, dict):
                cs = tls.get('tls_tls_handshake_ciphersuite_raw') or tls.get('tls_tls_handshake_ciphersuite')
                if cs:
                    if isinstance(cs, str):
                        cipher_list = cs.split()
                    elif isinstance(cs, list):
                        cipher_list = cs
            elif isinstance(tls, list):
                for tls_entry in tls:
                    if not isinstance(tls_entry, dict):
                        continue
                    cs = tls_entry.get('tls_tls_handshake_ciphersuite_raw') or tls_entry.get('tls_tls_handshake_ciphersuite')
                    if isinstance(cs, str):
                        cipher_list.extend(cs.split())
                    elif isinstance(cs, list):
                        cipher_list.extend(cs)

            for c in cipher_list:
                c = c.strip().lower()
                if not c:
                    continue
                if ',' in c:
                    parts = [p.strip() for p in c.split(',') if p.strip()]
                    ciphers_found.update(parts)
                else:
                    ciphers_found.add(c)

def main(foldername):
    ciphers_found = set()
    for root, dirs, files in os.walk(foldername):
        for file in files:
            if file.lower().endswith('.json'):
                filepath = os.path.join(root, file)
                print(f"Processing file: {filepath}")
                process_file(filepath, ciphers_found)

    if not ciphers_found:
        print("No cipher suites found in input files.")
        return

    category_counts = {'Secure': 0, 'Recommended': 0, 'Weak': 0, 'Insecure/Other': 0, 'Unknown': 0}
    for c in ciphers_found:
        category_counts[classify_cipher_suite(c)] += 1

    print("\nSummary of cipher suite classifications:")
    for cat in sorted(category_counts):
        print(f"  {cat}: {category_counts[cat]}")

    print(f"\nFound {len(ciphers_found)} unique cipher suites across all files:")
    for c in sorted(ciphers_found):
        cat = classify_cipher_suite(c)
        name = CIPHER_NAMES.get(c, "Unknown name")
        print(f"  {c} ({name}) : {cat}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <folder_path>")
        sys.exit(1)
    main(sys.argv[1])
