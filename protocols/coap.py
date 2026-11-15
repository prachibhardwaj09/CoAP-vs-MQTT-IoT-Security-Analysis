#!/usr/bin/env python3
"""
CoAP (RFC 7252) Packet Encoder and Decoder
Pure Python implementation of core Constrained Application Protocol packets for security & overhead analysis.
"""

import struct

# CoAP Message Types
CON = 0  # Confirmable
NON = 1  # Non-confirmable
ACK = 2  # Acknowledgement
RST = 3  # Reset

TYPE_NAMES = {CON: "CON", NON: "NON", ACK: "ACK", RST: "RST"}

# CoAP Request & Response Codes
EMPTY           = 0
GET             = 1   # 0.01
POST            = 2   # 0.02
PUT             = 3   # 0.03
DELETE          = 4   # 0.04
CREATED         = 65  # 2.01
DELETED         = 66  # 2.02
VALID           = 67  # 2.03
CHANGED         = 68  # 2.04
CONTENT         = 69  # 2.05
BAD_REQUEST     = 128 # 4.00
UNAUTHORIZED    = 129 # 4.01
NOT_FOUND       = 132 # 4.04
INTERNAL_ERROR  = 160 # 5.00

CODE_NAMES = {
    0: "EMPTY",
    1: "0.01 GET",
    2: "0.02 POST",
    3: "0.03 PUT",
    4: "0.04 DELETE",
    65: "2.01 Created",
    68: "2.04 Changed",
    69: "2.05 Content",
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    132: "4.04 Not Found",
    160: "5.00 Internal Server Error"
}

# Common CoAP Option Numbers
OPT_IF_MATCH       = 1
OPT_URI_HOST       = 3
OPT_ETAG           = 4
OPT_IF_NONE_MATCH  = 5
OPT_URI_PORT       = 7
OPT_LOCATION_PATH  = 8
OPT_URI_PATH       = 11
OPT_CONTENT_FORMAT = 12
OPT_MAX_AGE        = 14
OPT_URI_QUERY      = 15
OPT_ACCEPT         = 17
OPT_LOCATION_QUERY = 20

def encode_option_delta_length(val: int) -> tuple:
    """Encode delta or length into 4-bit nibble + extra bytes."""
    if val < 13:
        return val, b""
    elif val < 269:
        return 13, struct.pack("!B", val - 13)
    elif val < 65805:
        return 14, struct.pack("!H", val - 269)
    else:
        raise ValueError(f"Option value too large: {val}")

def encode_options(options: list) -> bytes:
    """
    Encode a list of (option_number, option_bytes) sorted by option_number.
    """
    sorted_opts = sorted(options, key=lambda x: x[0])
    encoded = bytearray()
    last_opt = 0

    for opt_num, opt_val in sorted_opts:
        if isinstance(opt_val, str):
            opt_val = opt_val.encode("utf-8")

        delta = opt_num - last_opt
        last_opt = opt_num

        delta_nibble, delta_ext = encode_option_delta_length(delta)
        len_nibble, len_ext = encode_option_delta_length(len(opt_val))

        header_byte = (delta_nibble << 4) | len_nibble
        encoded.append(header_byte)
        encoded.extend(delta_ext)
        encoded.extend(len_ext)
        encoded.extend(opt_val)

    return bytes(encoded)

def decode_option_delta_length(nibble: int, data: bytes, offset: int) -> tuple:
    if nibble < 13:
        return nibble, offset
    elif nibble == 13:
        val = data[offset] + 13
        return val, offset + 1
    elif nibble == 14:
        val = struct.unpack("!H", data[offset:offset+2])[0] + 269
        return val, offset + 2
    else:
        raise ValueError("Reserved option delta/length value 15")

def decode_options(data: bytes, offset: int) -> tuple:
    """Decode options until payload marker 0xFF or end of packet."""
    options = []
    current_opt = 0

    while offset < len(data):
        if data[offset] == 0xFF:
            # Payload marker found
            offset += 1
            break

        byte = data[offset]
        offset += 1
        delta_nibble = (byte >> 4) & 0x0F
        len_nibble = byte & 0x0F

        delta, offset = decode_option_delta_length(delta_nibble, data, offset)
        opt_len, offset = decode_option_delta_length(len_nibble, data, offset)

        current_opt += delta
        val = data[offset:offset+opt_len]
        offset += opt_len

        options.append((current_opt, val))

    return options, offset

def build_coap_packet(msg_type: int, code: int, message_id: int, token: bytes = b"", options: list = None, payload: bytes = b"") -> bytes:
    """Construct an RFC 7252 CoAP packet."""
    tkl = len(token) & 0x0F
    first_byte = (1 << 6) | ((msg_type & 0x03) << 4) | tkl
    header = struct.pack("!BBH", first_byte, code, message_id)

    packet = bytearray(header)
    if token:
        packet.extend(token[:8])

    if options:
        packet.extend(encode_options(options))

    if payload:
        packet.append(0xFF)  # Payload marker
        packet.extend(payload)

    return bytes(packet)

def parse_coap_packet(raw_data: bytes) -> dict:
    """Parse raw CoAP bytes into structured dictionary."""
    if len(raw_data) < 4:
        return {"error": "Packet too short (min 4 bytes for CoAP)"}

    first_byte, code, message_id = struct.unpack("!BBH", raw_data[:4])
    ver = (first_byte >> 6) & 0x03
    msg_type = (first_byte >> 4) & 0x03
    tkl = first_byte & 0x0F

    offset = 4
    token = raw_data[offset:offset+tkl]
    offset += tkl

    options_raw, offset = decode_options(raw_data, offset)
    payload = raw_data[offset:]

    # Parse common options like Uri-Path
    uri_paths = []
    for opt_num, opt_val in options_raw:
        if opt_num == OPT_URI_PATH:
            uri_paths.append(opt_val.decode("utf-8", errors="ignore"))

    uri_path = "/" + "/".join(uri_paths) if uri_paths else "/"

    return {
        "version": ver,
        "type": msg_type,
        "type_name": TYPE_NAMES.get(msg_type, f"TYPE_{msg_type}"),
        "code": code,
        "code_name": CODE_NAMES.get(code, f"CODE_{code}"),
        "message_id": message_id,
        "token": token.hex(),
        "uri_path": uri_path,
        "options_count": len(options_raw),
        "payload_bytes": payload,
        "payload_str": payload.decode("utf-8", errors="ignore"),
        "raw_size": len(raw_data)
    }

if __name__ == "__main__":
    # Self-test
    req = build_coap_packet(
        msg_type=CON,
        code=POST,
        message_id=0x1234,
        token=b"\xaa\xbb",
        options=[(OPT_URI_PATH, "sensors"), (OPT_URI_PATH, "temp")],
        payload=b'{"temperature": 29.2}'
    )
    print("CoAP packet bytes:", req.hex())
    parsed = parse_coap_packet(req)
    print("Parsed CoAP:", parsed)

