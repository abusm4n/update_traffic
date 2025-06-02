#!/usr/bin/env python3

#
# Extractor that is used for dumping PCAP file contents fotr the intl-iot dataset
# this tool dumps HTTP data only using tshark
#

import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
from joblib import Parallel, delayed
import socket
import pyshark

FILE = "../../dataset/iot-data/us/fridge/power/2019-04-25_18:57:02.171s.pcap"

def extract_tls_traffic(packet_file):
    def extract_packets_by_filter(packet_file, display_filter):
        collected_packets = []
        packets = pyshark.FileCapture(
            packet_file,
            display_filter=display_filter,
            use_json=True
        )
        for pkt in packets:
            try:
                ip_src = pkt.ip.src if hasattr(pkt, 'ip') else None
                ssl_layer = pkt.ssl

                collected_packets.append({
                    "SSL": {
                        'ssl.handshake.version': getattr(ssl_layer, 'handshake_version', None),
                        'ssl.handshake.type': getattr(ssl_layer, 'handshake_type', None),
                        'ssl.handshake.ciphersuites': getattr(ssl_layer, 'handshake_ciphersuites', None)
                    },
                    "IP": {
                        'ip.src': ip_src
                    }
                })
            except AttributeError as e:
                print(f"Skipping packet due to missing field: {e}")
                continue
        packets.close()
        return collected_packets

    client_hello_packets = extract_packets_by_filter(packet_file, "ssl.handshake.type == 1")

    return {
        "client_hello_packets": client_hello_packets
    }

print(extract_tls_traffic(FILE))