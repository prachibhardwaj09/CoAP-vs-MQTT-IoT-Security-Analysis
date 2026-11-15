#!/usr/bin/env python3
"""
Standard Libpcap (.pcap) File Generator
Creates genuine, Wireshark-compatible packet captures for TCP/UDP and IoT protocols.
"""

import struct
import time
import socket

def checksum16(data: bytes) -> int:
    """Calculate standard Internet 16-bit 1's complement checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

class PcapWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self.packets = []

    def _build_ip_header(self, src_ip: str, dst_ip: str, proto: int, payload_len: int, ident: int = 1) -> bytes:
        total_len = 20 + payload_len
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        header_no_chk = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_len, ident, 0x4000, 64, proto, 0, src_bytes, dst_bytes
        )
        chk = checksum16(header_no_chk)
        return struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0x00, total_len, ident, 0x4000, 64, proto, chk, src_bytes, dst_bytes
        )

    def _build_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
        udp_len = 8 + len(payload)
        # Pseudo-header for UDP checksum
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 17, udp_len)
        udp_no_chk = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        chk = checksum16(pseudo + udp_no_chk + payload)
        if chk == 0:
            chk = 0xFFFF
        udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, chk)
        ip_header = self._build_ip_header(src_ip, dst_ip, 17, len(udp_header) + len(payload))
        eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        return eth_header + ip_header + udp_header + payload

    def _build_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                          seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
        tcp_len = 20 + len(payload)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, tcp_len)
        offset_flags = (5 << 12) | (flags & 0xFFF)
        tcp_no_chk = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, 0, 0)
        chk = checksum16(pseudo + tcp_no_chk + payload)
        tcp_header = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, chk, 0)
        ip_header = self._build_ip_header(src_ip, dst_ip, 6, len(tcp_header) + len(payload))
        eth_header = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        return eth_header + ip_header + tcp_header + payload

    def add_udp_datagram(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ts: float = None):
        pkt = self._build_udp_packet(src_ip, dst_ip, src_port, dst_port, payload)
        self.packets.append((ts or time.time(), pkt))

    def add_tcp_segment(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                        seq: int, ack: int, flags: int, payload: bytes = b"", ts: float = None):
        pkt = self._build_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
        self.packets.append((ts or time.time(), pkt))

    def add_raw_packet(self, raw_ethernet_packet: bytes, ts: float = None):
        self.packets.append((ts or time.time(), raw_ethernet_packet))

    def save(self):
        """Write all accumulated packets to standard .pcap format."""
        # Libpcap global header: Magic 0xa1b2c3d4, v2.4, thiszone 0, sigfigs 0, snaplen 65535, LinkType 1 (Ethernet)
        global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        with open(self.filename, "wb") as f:
            f.write(global_header)
            for ts, pkt in self.packets:
                sec = int(ts)
                usec = int((ts - sec) * 1000000)
                pkt_hdr = struct.pack("<IIII", sec, usec, len(pkt), len(pkt))
                f.write(pkt_hdr + pkt)
        print(f"[+] Saved {len(self.packets)} packets to PCAP: {self.filename}")

