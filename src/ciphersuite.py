import json
import sys
from collections import Counter
import os

# Classification based on known TLS cipher suites (TLS 1.2 mainly)
# Source info: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4import json



# Classification based on known TLS cipher suites (TLS 1.2 mainly)
SECURE = {
    '1301', '1302', '1303',  # TLS 1.3
    'c02f', 'c02b', 'c030', 'c02c', 'cca9', 'cca8', 'ccaa', '009f', '009e',
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

def classify_cipher_suite(hexcode: str) -> str:
    h = hexcode.lower()
    if h.startswith('0x'):
        h = h[2:]
    h = h.zfill(4)
    if h in SECURE:
        return 'Secure'
    elif h in RECOMMENDED:
        return 'Recommended'
    elif h in WEAK:
        return 'Weak'
    elif h in INSECURE:
        return 'Insecure'
    else:
        return 'Unknown'

def main(filename):
    category_counts = Counter()

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
            except json.JSONDecodeError:
                continue

            tls = packet.get('layers', {}).get('tls', {})
            cipher_list = []

            if isinstance(tls, dict):
                cipher_list = tls.get('tls_tls_handshake_ciphersuite_raw') or tls.get('tls_tls_handshake_ciphersuite')
                if cipher_list and isinstance(cipher_list, str):
                    cipher_list = cipher_list.split()
            elif isinstance(tls, list):
                for tls_entry in tls:
                    if isinstance(tls_entry, dict):
                        ciphers = tls_entry.get('tls_tls_handshake_ciphersuite_raw') or tls_entry.get('tls_tls_handshake_ciphersuite')
                        if ciphers:
                            if isinstance(ciphers, str):
                                cipher_list.extend(ciphers.split())
                            elif isinstance(ciphers, list):
                                cipher_list.extend(ciphers)

            if not cipher_list:
                continue

            for c in cipher_list:
                c = c.strip().lower()
                if not c:
                    continue
                if ',' in c:
                    for p in [p.strip() for p in c.split(',') if p.strip()]:
                        cat = classify_cipher_suite(p)
                        category_counts[cat] += 1
                else:
                    cat = classify_cipher_suite(c)
                    category_counts[cat] += 1

    if not category_counts:
        print("No cipher suites found in input.")
        return

    print("Cipher suite category counts:")
    for cat in ["Secure", "Recommended", "Weak", "Insecure", "Unknown"]:
        print(f"  {cat}: {category_counts[cat]}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <packets.json>")
        sys.exit(1)
    main(sys.argv[1])
