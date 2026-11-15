#!/usr/bin/env python3
"""
Packet & Security Overhead Analyzer
Inspects PCAP files, analyzes exposed plaintext, and measures cryptographic overhead.
"""

import struct
import math
import os

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy to distinguish plaintext from encrypted data."""
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class PcapAnalyzer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packets = []
        self._parse()

    def _parse(self):
        if not os.path.exists(self.pcap_path):
            return

        with open(self.pcap_path, "rb") as f:
            raw = f.read()

        if len(raw) < 24:
            return

        magic = raw[:4]
        # Check standard pcap magic
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        else:
            endian = "<"

        offset = 24
        while offset + 16 <= len(raw):
            sec, usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", raw[offset:offset+16])
            offset += 16
            pkt_data = raw[offset:offset+incl_len]
            offset += incl_len

            parsed_pkt = self._dissect_packet(pkt_data, sec + usec / 1e6)
            if parsed_pkt:
                self.packets.append(parsed_pkt)

    def _dissect_packet(self, data: bytes, ts: float) -> dict:
        if len(data) < 14:
            return None

        # Ethernet
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:  # Not IPv4
            return None

        # IPv4
        ip_data = data[14:]
        if len(ip_data) < 20:
            return None

        ihl = (ip_data[0] & 0x0F) * 4
        proto = ip_data[9]
        total_len = struct.unpack("!H", ip_data[2:4])[0]
        payload = ip_data[ihl:]

        src_port, dst_port = 0, 0
        transport = "OTHER"
        app_data = b""

        if proto == 6:  # TCP
            transport = "TCP"
            if len(payload) >= 20:
                src_port, dst_port = struct.unpack("!HH", payload[:4])
                tcp_offset = ((payload[12] >> 4) & 0x0F) * 4
                app_data = payload[tcp_offset:]
        elif proto == 17:  # UDP
            transport = "UDP"
            if len(payload) >= 8:
                src_port, dst_port = struct.unpack("!HH", payload[:4])
                app_data = payload[8:]

        return {
            "timestamp": ts,
            "total_bytes": len(data),
            "transport": transport,
            "src_port": src_port,
            "dst_port": dst_port,
            "app_bytes": len(app_data),
            "raw_payload": app_data
        }

    def get_summary(self, sensitive_keywords: list = None) -> dict:
        if sensitive_keywords is None:
            sensitive_keywords = ["temp", "password", "sensor", "api_key", "secret", "voltage", "token"]

        total_bytes = sum(p["total_bytes"] for p in self.packets)
        app_bytes = sum(p["app_bytes"] for p in self.packets)
        packet_count = len(self.packets)

        all_payload = b"".join(p["raw_payload"] for p in self.packets)
        exposed_keywords = []

        lower_payload = all_payload.lower()
        for kw in sensitive_keywords:
            if kw.encode("utf-8").lower() in lower_payload:
                exposed_keywords.append(kw)

        entropy = calculate_entropy(all_payload) if all_payload else 0.0
        is_encrypted = (entropy > 6.0 and len(exposed_keywords) == 0) or any(
            p["raw_payload"].startswith(b"\x16\x03") or p["raw_payload"].startswith(b"\x17\x03")
            for p in self.packets if p["raw_payload"]
        )

        transport = self.packets[0]["transport"] if self.packets else "N/A"

        return {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "app_bytes": app_bytes,
            "transport": transport,
            "entropy": round(entropy, 2),
            "is_encrypted": is_encrypted,
            "exposed_keywords": exposed_keywords,
            "exposure_status": "EXPOSED / VULNERABLE" if exposed_keywords else ("ENCRYPTED / CONFIDENTIAL" if is_encrypted else "NO PAYLOAD")
        }

def format_comparison_table(results: dict) -> str:
    """Format multiple scenario results into an ASCII comparison table."""
    headers = ["Metric / Parameter", "MQTT (Plain TCP)", "MQTT (TLS / TCP)", "CoAP (Plain UDP)", "CoAP (DTLS / UDP)"]
    rows = [
        ("Transport Layer",
         results.get("mqtt_plain", {}).get("transport", "TCP"),
         results.get("mqtt_tls", {}).get("transport", "TCP"),
         results.get("coap_plain", {}).get("transport", "UDP"),
         results.get("coap_dtls", {}).get("transport", "UDP")),

        ("Port Used",
         "1883", "8883", "5683", "5684"),

        ("Security Layer",
         "None (Plaintext)", "TLS 1.2 / 1.3", "None (Plaintext)", "DTLS 1.2"),

        ("Total Packets Transferred",
         str(results.get("mqtt_plain", {}).get("packet_count", "-")),
         str(results.get("mqtt_tls", {}).get("packet_count", "-")),
         str(results.get("coap_plain", {}).get("packet_count", "-")),
         str(results.get("coap_dtls", {}).get("packet_count", "-"))),

        ("Total Network Bytes",
         f"{results.get('mqtt_plain', {}).get('total_bytes', 0)} B",
         f"{results.get('mqtt_tls', {}).get('total_bytes', 0)} B",
         f"{results.get('coap_plain', {}).get('total_bytes', 0)} B",
         f"{results.get('coap_dtls', {}).get('total_bytes', 0)} B"),

        ("Payload Entropy (0-8)",
         f"{results.get('mqtt_plain', {}).get('entropy', 0.0)}",
         f"{results.get('mqtt_tls', {}).get('entropy', 0.0)}",
         f"{results.get('coap_plain', {}).get('entropy', 0.0)}",
         f"{results.get('coap_dtls', {}).get('entropy', 0.0)}"),

        ("Exposed Sensitive Data",
         ", ".join(results.get("mqtt_plain", {}).get("exposed_keywords", [])) or "None",
         "None (Encrypted)",
         ", ".join(results.get("coap_plain", {}).get("exposed_keywords", [])) or "None",
         "None (Encrypted)"),

        ("Security Confidentiality Status",
         results.get("mqtt_plain", {}).get("exposure_status", "-"),
         results.get("mqtt_tls", {}).get("exposure_status", "-"),
         results.get("coap_plain", {}).get("exposure_status", "-"),
         results.get("coap_dtls", {}).get("exposure_status", "-")),
    ]

    col_widths = [max(len(str(item)) for item in [h] + [r[i] for r in rows]) + 2 for i, h in enumerate(headers)]

    sep_line = "+" + "+".join("-" * w for w in col_widths) + "+"
    hdr_line = "|" + "|".join(f" {h}".ljust(w) for h, w in zip(headers, col_widths)) + "|"

    table_lines = [sep_line, hdr_line, sep_line]
    for r in rows:
        row_str = "|" + "|".join(f" {val}".ljust(w) for val, w in zip(r, col_widths)) + "|"
        table_lines.append(row_str)
    table_lines.append(sep_line)

    return "\n".join(table_lines)

