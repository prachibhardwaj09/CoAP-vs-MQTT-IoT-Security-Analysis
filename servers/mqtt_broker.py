#!/usr/bin/env python3
"""
Lightweight MQTT Broker (Plaintext TCP / TLS Encrypted)
Supports MQTT 3.1.1 CONNECT, PUBLISH, PUBACK, PINGREQ, DISCONNECT.
"""

import socket
import ssl
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocols.mqtt import (
    CONNECT, PUBLISH, PINGREQ, DISCONNECT,
    build_connack_packet, build_puback_packet, parse_mqtt_packet
)

CERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")

class MQTTBroker:
    def __init__(self, host="127.0.0.1", port=1883, use_tls=False, verbose=True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.verbose = verbose
        self.running = False
        self.server_sock = None
        self.received_messages = []
        self.client_threads = []

    def log(self, msg):
        if self.verbose:
            proto_tag = "[MQTT-TLS Broker]" if self.use_tls else "[MQTT Broker]"
            print(f"{proto_tag} {msg}")

    def start(self):
        self.running = True
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(5)

        if self.use_tls:
            srv_crt = os.path.join(CERTS_DIR, "server.crt")
            srv_key = os.path.join(CERTS_DIR, "server.key")
            ca_crt = os.path.join(CERTS_DIR, "ca.crt")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=srv_crt, keyfile=srv_key)
            self.server_sock = ctx.wrap_socket(raw_sock, server_side=True)
            self.log(f"Listening with TLS on {self.host}:{self.port} (Port 8883 standard MQTTS)")
        else:
            self.server_sock = raw_sock
            self.log(f"Listening on {self.host}:{self.port} (Plaintext TCP Port 1883)")

        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                self.client_threads.append(t)
                t.start()
            except Exception:
                break

    def _handle_client(self, sock, addr):
        self.log(f"New client connected from {addr[0]}:{addr[1]}")
        try:
            while self.running:
                data = sock.recv(4096)
                if not data:
                    break

                parsed = parse_mqtt_packet(data)
                pkt_type = parsed.get("packet_type")

                if pkt_type == CONNECT:
                    cid = parsed.get("client_id", "unknown")
                    user = parsed.get("username")
                    pw = parsed.get("password")
                    self.log(f"Received CONNECT: ClientID='{cid}', User='{user}', Pass='{pw}'")
                    connack = build_connack_packet(session_present=0, return_code=0)
                    sock.sendall(connack)
                    self.log("Sent CONNACK: Connection Accepted (Code 0)")

                elif pkt_type == PUBLISH:
                    topic = parsed.get("topic", "")
                    payload = parsed.get("payload_str", "")
                    qos = parsed.get("qos", 0)
                    pkt_id = parsed.get("packet_id", 1)
                    self.log(f"Received PUBLISH on topic '{topic}': QoS={qos}, Payload={payload}")
                    self.received_messages.append({"topic": topic, "payload": payload, "qos": qos})

                    if qos == 1 and pkt_id:
                        puback = build_puback_packet(pkt_id)
                        sock.sendall(puback)
                        self.log(f"Sent PUBACK for PacketID={pkt_id}")

                elif pkt_type == DISCONNECT:
                    self.log("Received DISCONNECT from client")
                    break
        except Exception as e:
            self.log(f"Client connection closed: {e}")
        finally:
            sock.close()

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        self.log("Broker stopped.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MQTT Broker")
    parser.add_argument("--tls", action="store_true", help="Enable TLS mode (port 8883)")
    parser.add_argument("--port", type=int, default=None, help="Port to listen on")
    args = parser.parse_args()

    port = args.port or (8883 if args.tls else 1883)
    broker = MQTTBroker(port=port, use_tls=args.tls)
    broker.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        broker.stop()

