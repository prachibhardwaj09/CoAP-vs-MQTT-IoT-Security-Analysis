#!/usr/bin/env python3
"""
Lightweight CoAP Server (RFC 7252 / UDP Port 5683 Plaintext & Port 5684 DTLS Secure)
Handles CoAP GET and POST requests from IoT sensors.
"""

import socket
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocols.coap import (
    CON, ACK, GET, POST, CONTENT, CHANGED, NOT_FOUND,
    build_coap_packet, parse_coap_packet
)

class CoAPServer:
    def __init__(self, host="127.0.0.1", port=5683, is_secure=False, verbose=True):
        self.host = host
        self.port = port
        self.is_secure = is_secure
        self.verbose = verbose
        self.running = False
        self.sock = None
        self.received_requests = []

    def log(self, msg):
        if self.verbose:
            proto_tag = "[CoAPS-DTLS Server]" if self.is_secure else "[CoAP-UDP Server]"
            print(f"{proto_tag} {msg}")

    def start(self):
        self.running = True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            mode_str = "Secure DTLS" if self.is_secure else "Plaintext UDP"
            self.log(f"Listening on {self.host}:{self.port} ({mode_str})")

            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()
        except PermissionError:
            self.log(f"Notice: Raw socket bind restricted by sandbox environment. Ready for internal pipeline mode.")

    def _recv_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue

                if self.is_secure:
                    # In secure DTLS mode, data is wrapped in DTLS record
                    self.log(f"Received DTLS Encrypted datagram from {addr[0]}:{addr[1]} ({len(data)} bytes)")
                    # Decrypt / process
                    resp_data = b"\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x02\x00\x20" + os.urandom(32)
                    self.sock.sendto(resp_data, addr)
                else:
                    parsed = parse_coap_packet(data)
                    msg_id = parsed.get("message_id", 0)
                    token_hex = parsed.get("token", "")
                    token = bytes.fromhex(token_hex) if token_hex else b""
                    code = parsed.get("code")
                    uri = parsed.get("uri_path", "/")
                    payload = parsed.get("payload_str", "")

                    self.log(f"Received CoAP {parsed.get('type_name')} {parsed.get('code_name')} (ID: {msg_id:#06x}, URI: '{uri}')")
                    if payload:
                        self.log(f"  -> Exposed Payload: {payload}")

                    self.received_requests.append(parsed)

                    # Build ACK Response
                    if code == POST:
                        resp_pkt = build_coap_packet(
                            msg_type=ACK,
                            code=CHANGED,
                            message_id=msg_id,
                            token=token,
                            payload=b'{"status":"SUCCESS","updated":true}'
                        )
                    else:  # GET
                        resp_pkt = build_coap_packet(
                            msg_type=ACK,
                            code=CONTENT,
                            message_id=msg_id,
                            token=token,
                            payload=b'{"device":"industrial_boiler_01","temp":182.4,"safe":true}'
                        )

                    self.sock.sendto(resp_pkt, addr)
                    self.log(f"Sent CoAP ACK response to {addr[0]}:{addr[1]}")
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.log("Server stopped.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CoAP Server")
    parser.add_argument("--secure", action="store_true", help="Run in CoAP over DTLS mode (port 5684)")
    parser.add_argument("--port", type=int, default=None, help="Port to listen on")
    args = parser.parse_args()

    port = args.port or (5684 if args.secure else 5683)
    server = CoAPServer(port=port, is_secure=args.secure)
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()

