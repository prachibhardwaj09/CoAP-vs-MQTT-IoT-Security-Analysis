#!/usr/bin/env python3
"""
MQTT 3.1.1 Packet Encoder and Decoder
Pure Python implementation of core MQTT control packets for security & overhead analysis.
"""

import struct

# MQTT Control Packet Types
CONNECT     = 1
CONNACK     = 2
PUBLISH     = 3
PUBACK      = 4
SUBSCRIBE   = 8
SUBACK      = 9
PINGREQ     = 12
PINGRESP    = 13
DISCONNECT  = 14

PACKET_NAMES = {
    CONNECT: "CONNECT",
    CONNACK: "CONNACK",
    PUBLISH: "PUBLISH",
    PUBACK: "PUBACK",
    SUBSCRIBE: "SUBSCRIBE",
    SUBACK: "SUBACK",
    PINGREQ: "PINGREQ",
    PINGRESP: "PINGRESP",
    DISCONNECT: "DISCONNECT"
}

def encode_remaining_length(length: int) -> bytes:
    """Encode remaining length according to MQTT variable byte integer."""
    encoded = bytearray()
    while True:
        encoded_byte = length % 128
        length = length // 128
        if length > 0:
            encoded_byte |= 128
        encoded.append(encoded_byte)
        if length == 0:
            break
    return bytes(encoded)

def decode_remaining_length(data: bytes, offset: int = 1):
    """Decode remaining length and return (length, bytes_consumed)."""
    multiplier = 1
    value = 0
    idx = offset
    while True:
        if idx >= len(data):
            return 0, idx - offset
        digit = data[idx]
        value += (digit & 127) * multiplier
        multiplier *= 128
        idx += 1
        if (digit & 128) == 0:
            break
    return value, idx - offset

def build_connect_packet(client_id: str, username: str = None, password: str = None, keep_alive: int = 60) -> bytes:
    """Construct an MQTT CONNECT packet."""
    # Variable Header: Protocol Name (4 bytes) + Level (1 byte) + Flags (1 byte) + KeepAlive (2 bytes)
    proto_name = b"\x00\x04MQTT"
    proto_level = b"\x04"  # 3.1.1
    flags = 0x02  # Clean session = 1

    payload = bytearray()
    # Client ID
    cid_bytes = client_id.encode("utf-8")
    payload += struct.pack("!H", len(cid_bytes)) + cid_bytes

    if username is not None:
        flags |= 0x80  # Username flag
        u_bytes = username.encode("utf-8")
        payload += struct.pack("!H", len(u_bytes)) + u_bytes

    if password is not None:
        flags |= 0x40  # Password flag
        p_bytes = password.encode("utf-8")
        payload += struct.pack("!H", len(p_bytes)) + p_bytes

    connect_flags = bytes([flags])
    keep_alive_bytes = struct.pack("!H", keep_alive)

    var_header = proto_name + proto_level + connect_flags + keep_alive_bytes
    rem_len = len(var_header) + len(payload)

    fixed_header = bytes([CONNECT << 4]) + encode_remaining_length(rem_len)
    return fixed_header + var_header + bytes(payload)

def build_connack_packet(session_present: int = 0, return_code: int = 0) -> bytes:
    """Construct an MQTT CONNACK packet (0 = Connection Accepted)."""
    return bytes([CONNACK << 4, 0x02, session_present & 0x01, return_code & 0xFF])

def build_publish_packet(topic: str, payload_data: bytes, qos: int = 0, packet_id: int = 1) -> bytes:
    """Construct an MQTT PUBLISH packet."""
    topic_bytes = topic.encode("utf-8")
    var_header = struct.pack("!H", len(topic_bytes)) + topic_bytes

    if qos > 0:
        var_header += struct.pack("!H", packet_id)

    flags = (qos & 0x03) << 1
    fixed_byte1 = (PUBLISH << 4) | flags
    rem_len = len(var_header) + len(payload_data)

    return bytes([fixed_byte1]) + encode_remaining_length(rem_len) + var_header + payload_data

def build_puback_packet(packet_id: int) -> bytes:
    """Construct an MQTT PUBACK packet."""
    return bytes([PUBACK << 4, 0x02]) + struct.pack("!H", packet_id)

def build_disconnect_packet() -> bytes:
    """Construct an MQTT DISCONNECT packet."""
    return bytes([DISCONNECT << 4, 0x00])

def parse_mqtt_packet(raw_data: bytes) -> dict:
    """Parse raw MQTT bytes and extract readable fields."""
    if len(raw_data) < 2:
        return {"error": "Packet too short"}

    first_byte = raw_data[0]
    packet_type = (first_byte >> 4) & 0x0F
    flags = first_byte & 0x0F

    rem_len, len_bytes = decode_remaining_length(raw_data, 1)
    offset = 1 + len_bytes

    result = {
        "packet_type": packet_type,
        "type_name": PACKET_NAMES.get(packet_type, f"UNKNOWN({packet_type})"),
        "flags": flags,
        "remaining_length": rem_len,
        "raw_size": len(raw_data)
    }

    if packet_type == CONNECT:
        # Check protocol name
        if len(raw_data) >= offset + 6:
            p_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
            p_name = raw_data[offset+2:offset+2+p_len].decode("utf-8", errors="ignore")
            offset += 2 + p_len
            level = raw_data[offset]
            c_flags = raw_data[offset+1]
            keep_alive = struct.unpack("!H", raw_data[offset+2:offset+4])[0]
            offset += 4

            # Client ID
            cid_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
            offset += 2
            cid = raw_data[offset:offset+cid_len].decode("utf-8", errors="ignore")
            offset += cid_len

            username = None
            password = None
            if c_flags & 0x80:
                u_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
                offset += 2
                username = raw_data[offset:offset+u_len].decode("utf-8", errors="ignore")
                offset += u_len
            if c_flags & 0x40:
                p_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
                offset += 2
                password = raw_data[offset:offset+p_len].decode("utf-8", errors="ignore")
                offset += p_len

            result.update({
                "protocol": p_name,
                "protocol_level": level,
                "client_id": cid,
                "username": username,
                "password": password,
                "keep_alive": keep_alive
            })

    elif packet_type == PUBLISH:
        if len(raw_data) >= offset + 2:
            t_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
            offset += 2
            topic = raw_data[offset:offset+t_len].decode("utf-8", errors="ignore")
            offset += t_len

            qos = (flags >> 1) & 0x03
            pkt_id = None
            if qos > 0 and len(raw_data) >= offset + 2:
                pkt_id = struct.unpack("!H", raw_data[offset:offset+2])[0]
                offset += 2

            payload = raw_data[offset:]
            result.update({
                "topic": topic,
                "qos": qos,
                "packet_id": pkt_id,
                "payload_bytes": payload,
                "payload_str": payload.decode("utf-8", errors="ignore")
            })

    elif packet_type == CONNACK:
        if len(raw_data) >= offset + 2:
            session_present = raw_data[offset]
            ret_code = raw_data[offset+1]
            result.update({"session_present": session_present, "return_code": ret_code})

    return result

if __name__ == "__main__":
    # Self-test
    pkt = build_connect_packet("test_node_01", "admin", "secret_pass123")
    parsed = parse_mqtt_packet(pkt)
    print("Parsed CONNECT:", parsed)

    pub = build_publish_packet("home/temperature", b'{"temp": 24.5}')
    parsed_pub = parse_mqtt_packet(pub)
    print("Parsed PUBLISH:", parsed_pub)

