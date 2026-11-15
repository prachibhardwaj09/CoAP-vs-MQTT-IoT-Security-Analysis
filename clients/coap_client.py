#!/usr/bin/env python3
"""
Lightweight CoAP Client (RFC 7252 / UDP Port 5683 Plaintext & Port 5684 DTLS Secure)
Transmits sensor telemetry requests to CoAP server.
"""

import socket
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocols.coap import (
    CON, POST, GET, OPT_URI_PATH, OPT_CONTENT_FORMAT,
    build_coap_packet, parse_coap_packet
)

class CoAPClient:
    def __init__(self, host="127.0.0.1", port=5683, is_secure=False, verbose=True):
        self.host = host
        self.port = port
        self.is_secure = is_secure
        self.verbose = verbose
        self.sock = None

    def log(self, msg):
        if self.verbose:
            proto_tag = "[CoAPS-DTLS Client]" if self.is_secure else "[CoAP-UDP Client]"
            print(f"{proto_tag} {msg}")

    def send_post_telemetry(self, uri_path="sensors/boiler/telemetry", payload='{"boiler_id":"UNIT_4A","temperature":184.2,"pressure_psi":145.0,"auth_token":"COAP_SECRET_KEY_7761"}'):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3.0)

        path_segments = [p for p in uri_path.split("/") if p]
        options = [(OPT_URI_PATH, seg) for seg in path_segments]
        options.append((OPT_CONTENT_FORMAT, b"\x32"))  # 50 = application/json

        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = payload

        if self.is_secure:
            self.log(f"Preparing DTLS encrypted datagram for {self.host}:{self.port}...")
            # Simulate/send DTLS record: Header (13 bytes) + encrypted payload + MAC
            dtls_rec = b"\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x01" + len(payload_bytes + b"\x00"*20).to_bytes(2, "big") + os.urandom(len(payload_bytes) + 20)
            self.sock.sendto(dtls_rec, (self.host, self.port))
            self.log(f"Sent DTLS Encrypted CoAP Record ({len(dtls_rec)} bytes). Plaintext is hidden.")
            try:
                resp_data, _ = self.sock.recvfrom(4096)
                self.log(f"Received DTLS Encrypted Response ({len(resp_data)} bytes)")
            except Exception:
                pass
        else:
            pkt = build_coap_packet(
                msg_type=CON,
                code=POST,
                message_id=0x5a1b,
                token=b"\x12\x34",
                options=options,
                payload=payload_bytes
            )
            self.log(f"Sending CoAP CON POST to udp://{self.host}:{self.port}/{uri_path}")
            self.log(f"  -> Exposed Payload in UDP datagram: {payload}")
            self.sock.sendto(pkt, (self.host, self.port))

            try:
                resp_data, _ = self.sock.recvfrom(4096)
                parsed = parse_coap_packet(resp_data)
                self.log(f"Received CoAP {parsed.get('type_name')} {parsed.get('code_name')} (ID: {parsed.get('message_id', 0):#06x})")
                self.log(f"  -> Response Payload: {parsed.get('payload_str')}")
            except Exception as e:
                self.log(f"Awaiting response: {e}")

        self.sock.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CoAP Client")
    parser.add_argument("--secure", action="store_true", help="Use CoAP over DTLS (port 5684)")
    parser.add_argument("--port", type=int, default=None, help="Port to connect to")
    args = parser.parse_args()

    port = args.port or (5684 if args.secure else 5683)
    cli = CoAPClient(port=port, is_secure=args.secure)
    cli.send_post_telemetry()

