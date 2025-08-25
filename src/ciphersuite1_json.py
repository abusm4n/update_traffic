import json
import sys

# Classification based on known TLS cipher suites (TLS 1.2 mainly)
# Source info: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
SECURE = {
    # TLS 1.3 ciphersuites (hex without 0x)
    '1301', '1302', '1303',  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    # ECDHE + AES-GCM or ChaCha20 suites (TLS 1.2)
    'c02f', 'c02b', 'c030', 'c02c', 'cca9', 'cca8', 'ccaa', '009f', '009e',
}
RECOMMENDED = {
    # DHE + AES-GCM
    '009f', '009e',
    # ECDHE + AES-CBC (less ideal but forward secrecy)
    'c023', 'c027', 'c00a', 'c014', 'c009', 'c013',
}
WEAK = {
    # AES-CBC suites with RSA key exchange, SHA1 MAC, no forward secrecy
    '002f', '0033', '0035', '0039', '003c', '003d', '009c', '009d',
}
INSECURE = {
    # SSLv3 or null/anonymous suites (not found in your sample but included for completeness)
    '0000', '00ff',  # 00ff is renegotiation SCSV (not a cipher suite), treat separately if needed
}

def classify_cipher_suite(hexcode: str) -> str:
    h = hexcode.lower()
    # Remove 0x prefix if present
    if h.startswith('0x'):
        h = h[2:]
    # Normalize to 4 characters
    h = h.zfill(4)
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

def main(filename):
    with open(filename, 'r') as f:
        ciphers_found = set()
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
            except json.JSONDecodeError:
                continue

            tls = packet.get('layers', {}).get('tls', {})

            # Handle tls as dict or list
            if isinstance(tls, dict):
                cipher_list = tls.get('tls_tls_handshake_ciphersuite_raw') or tls.get('tls_tls_handshake_ciphersuite')
                if not cipher_list:
                    continue
            elif isinstance(tls, list):
                cipher_list = []
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
            else:
                # unexpected type, skip packet
                continue

            if isinstance(cipher_list, str):
                cipher_list = cipher_list.split()

            # Clean and collect cipher suites
            for c in cipher_list:
                c = c.strip().lower()
                if not c:
                    continue
                if ',' in c:
                    parts = c.split(',')
                    for p in parts:
                        p = p.strip()
                        if p:
                            ciphers_found.add(p)
                else:
                    ciphers_found.add(c)

        if not ciphers_found:
            print("No cipher suites found in input.")
            return

        print(f"Found {len(ciphers_found)} unique cipher suites:")
        for c in sorted(ciphers_found):
            cat = classify_cipher_suite(c)
            print(f"  {c} : {cat}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <packets.json>")
        sys.exit(1)
    main(sys.argv[1])
