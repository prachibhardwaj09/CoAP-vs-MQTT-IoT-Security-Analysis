#!/usr/bin/env python3
"""
Lightweight MQTT Client (Plaintext TCP / TLS Encrypted)
Publishes telemetry data to MQTT broker with authentication credentials.
"""

import socket
import ssl
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocols.mqtt import (
    build_connect_packet, build_publish_packet, build_disconnect_packet, parse_mqtt_packet
)

CERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")

class MQTTClient:
    def __init__(self, host="127.0.0.1", port=1883, use_tls=False, verbose=True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.verbose = verbose
        self.sock = None

    def log(self, msg):
        if self.verbose:
            proto_tag = "[MQTT-TLS Client]" if self.use_tls else "[MQTT Client]"
            print(f"{proto_tag} {msg}")

    def connect(self, client_id="esp32_iot_sensor", username="admin_operator", password="LabSecretPassword@2026"):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(5.0)

        if self.use_tls:
            ca_crt = os.path.join(CERTS_DIR, "ca.crt")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cafile=ca_crt)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            self.sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            self.log(f"Initiating TLS connection to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            cipher = self.sock.cipher()
            self.log(f"TLS Handshake completed! Cipher: {cipher[0]}, Version: {cipher[1]}")
        else:
            self.sock = raw_sock
            self.log(f"Initiating TCP connection to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            self.log("TCP 3-way handshake established.")

        # Send CONNECT packet
        conn_pkt = build_connect_packet(client_id, username=username, password=password)
        self.sock.sendall(conn_pkt)
        self.log(f"Sent CONNECT packet (ClientID: {client_id}, User: {username}, Pass: {password})")

        # Read CONNACK
        ack_data = self.sock.recv(1024)
        parsed = parse_mqtt_packet(ack_data)
        if parsed.get("return_code") == 0:
            self.log("Received CONNACK: Connection Accepted")
            return True
        else:
            self.log(f"Connection refused with code: {parsed.get('return_code')}")
            return False

    def publish(self, topic="skit/lab/iot/temperature", payload='{"device_id":"sensor_temp_01","temperature":28.6,"humidity":58.2,"status":"CRITICAL_HIGH","api_key":"skit_secret_key_9981"}', qos=1, packet_id=1):
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        else:
            payload_bytes = payload

        pub_pkt = build_publish_packet(topic, payload_bytes, qos=qos, packet_id=packet_id)
        self.sock.sendall(pub_pkt)
        self.log(f"Sent PUBLISH on topic '{topic}': Payload={payload}")

        if qos == 1:
            ack_data = self.sock.recv(1024)
            parsed = parse_mqtt_packet(ack_data)
            self.log(f"Received PUBACK for PacketID={parsed.get('packet_id', packet_id)}")

    def disconnect(self):
        if self.sock:
            disc_pkt = build_disconnect_packet()
            try:
                self.sock.sendall(disc_pkt)
                self.log("Sent DISCONNECT packet.")
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.log("TCP connection closed.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MQTT Client")
    parser.add_argument("--tls", action="store_true", help="Connect with TLS (port 8883)")
    parser.add_argument("--port", type=int, default=None, help="Port to connect to")
    args = parser.parse_args()

    port = args.port or (8883 if args.tls else 1883)
    cli = MQTTClient(port=port, use_tls=args.tls)
    if cli.connect():
        time.sleep(0.5)
        cli.publish()
        time.sleep(0.5)
        cli.disconnect()

