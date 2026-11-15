# CoAP vs MQTT: Security and Overhead Analysis

Mini project for Cyber Security Lab (7CIT4-22 / 7CS4-22), Department of CSE / CSE (IoT), SKIT Jaipur (RTU Kota).

---

## 1. Project Overview

In Experiment 4 of our lab syllabus, we learned how to capture and inspect TCP and UDP client-server traffic using Wireshark and `tcpdump`. 

This mini project builds on that experiment by analyzing the two most widely used IoT messaging protocols:
- **MQTT:** Runs over **TCP** (connection-oriented, uses ports 1883 for plaintext and 8883 for TLS).
- **CoAP:** Runs over **UDP** (connectionless, uses ports 5683 for plaintext and 5684 for DTLS).

The project demonstrates:
1. How plaintext MQTT and CoAP expose sensitive information (credentials, topics, sensor values) to network sniffing.
2. How applying TLS to MQTT and DTLS to CoAP protects the data.
3. The trade-offs in terms of packet counts, total byte overhead, and Shannon entropy.

---

## 2. Tech Stack

- **Language:** Python 3 (uses standard library modules: `socket`, `ssl`, `struct`, `threading`, `json`).
- **Capture Tools:** Wireshark and `tcpdump`.
- **Dependencies:** None. Runs directly on macOS, Linux, and Windows without needing third-party packages or external broker installations.

---

## 3. Project Structure

```text
├── certs/                      # Self-signed X.509 certs for TLS/DTLS testing
│   ├── generate_certs.py       # Certificate generator script
│   ├── ca.crt, ca.key
│   └── server.crt, server.key
├── protocols/                  # Protocol encoding and decoding
│   ├── mqtt.py                 # MQTT 3.1.1 packet parser & builder
│   └── coap.py                 # RFC 7252 CoAP packet parser & builder
├── servers/
│   ├── mqtt_broker.py          # Standalone MQTT broker (TCP 1883 / TLS 8883)
│   └── coap_server.py          # Standalone CoAP UDP server (UDP 5683 / DTLS 5684)
├── clients/
│   ├── mqtt_client.py          # MQTT client publishing telemetry & credentials
│   └── coap_client.py          # CoAP client sending POST requests
├── utils/
│   ├── pcap_writer.py          # Script to generate standard .pcap files
│   └── packet_analyzer.py      # Entropy and credential leak detector
├── pcaps/                      # Output capture files for Wireshark
│   ├── 01_mqtt_plaintext_tcp.pcap
│   ├── 02_mqtt_tls_tcp.pcap
│   ├── 03_coap_plaintext_udp.pcap
│   ├── 04_coap_dtls_udp.pcap
│   ├── results_summary.json
│   └── results_summary.txt
├── scripts/
│   ├── capture_tcpdump.sh      # Shell script to capture live loopback traffic
│   └── wireshark_guide.md      # Filter guide and screenshot notes
├── main.py                     # CLI menu to run individual tests
└── run_full_experiment.py      # Script to run all 4 tests and print the comparison
```

---

## 4. How to Run

### Step 1: Run the Complete Test
Run the automated test script to execute all four scenarios, generate the PCAP files, and print the results:

```bash
python3 run_full_experiment.py
```

### Step 2: Use the Interactive Menu (Optional)
If you want to run one protocol at a time or inspect a specific capture:

```bash
python3 main.py
```

---

## 5. Experimental Results

The table below shows the data collected from the four packet captures:

| Parameter | MQTT (Plaintext TCP) | MQTT (TLS / TCP) | CoAP (Plaintext UDP) | CoAP (DTLS / UDP) |
|---|---|---|---|---|
| **Transport Layer** | TCP | TCP | UDP | UDP |
| **Port** | 1883 | 8883 | 5683 | 5684 |
| **Security** | None | TLS 1.2 / 1.3 | None | DTLS 1.2 |
| **Total Packets** | 12 | 15 | 2 | 11 |
| **Total Bytes** | 865 B | 2,812 B | 291 B | 2,030 B |
| **Shannon Entropy** | 5.42 | 7.38 | 5.46 | 7.49 |
| **Exposed Plaintext** | Username, Password, Topic, JSON Payload | None (Encrypted) | URI Path, JSON Payload | None (Encrypted) |
| **Status** | Vulnerable | Secure | Vulnerable | Secure |

### Observations:
1. **Cleartext Exposure:** In plaintext MQTT, the client ID, username, password, and payload are clearly visible. In plaintext CoAP, the URI path and sensor payload can be read directly from the UDP packet.
2. **Transport Differences:** CoAP over UDP completes a request-response cycle in only 2 packets (291 bytes) because UDP does not require a 3-way handshake. MQTT over TCP needs 12 packets (865 bytes) due to connection establishment, ACKs, and teardown.
3. **Encryption Overhead:** Enabling TLS on MQTT and DTLS on CoAP increases the byte count significantly (from ~865 B to 2,812 B on MQTT, and 291 B to 2,030 B on CoAP). Most of this extra data comes from the initial certificate exchange and cryptographic handshake.
4. **Efficiency:** CoAP with DTLS uses fewer total bytes and packets than MQTT with TLS while still providing end-to-end encryption.

---

## 6. Wireshark Inspection

To examine the captures:
1. Open Wireshark and load any file from the `pcaps/` folder.
2. Use the display filters below:
   - **Plaintext MQTT:** `mqtt` or `tcp.port == 1883`
     *(Right-click packet -> Follow -> TCP Stream to see the raw text)*
   - **Encrypted MQTT:** `tls` or `tcp.port == 8883`
   - **Plaintext CoAP:** `coap` or `udp.port == 5683`
   - **Encrypted CoAP:** `dtls` or `udp.port == 5684`

### Command-line Inspection (tcpdump)
You can also inspect the packet payloads directly in the terminal:

```bash
# View plaintext MQTT data
tcpdump -r pcaps/01_mqtt_plaintext_tcp.pcap -X

# View plaintext CoAP datagrams
tcpdump -r pcaps/03_coap_plaintext_udp.pcap -X
```

---

## 7. Viva Questions & Answers

**Q1: What is the main difference between MQTT and CoAP at the transport layer?**  
**Ans:** MQTT uses TCP (reliable, connection-oriented with a 3-way handshake), while CoAP uses UDP (connectionless and lightweight datagrams).

**Q2: Why is plaintext MQTT a security risk?**  
**Ans:** The standard MQTT protocol on port 1883 sends packets in cleartext. Anyone sniffing the network can capture the `CONNECT` packet to steal usernames and passwords, and read the `PUBLISH` packet payloads.

**Q3: How does DTLS differ from standard TLS?**  
**Ans:** TLS relies on a reliable transport stream (TCP). DTLS (RFC 6347) is modified to run over unreliable datagrams (UDP). It adds sequence numbers, packet retransmission handling, and a `Hello Verify Request` cookie exchange to prevent denial-of-service/amplification attacks.

**Q4: What causes the large increase in bytes when enabling TLS or DTLS?**  
**Ans:** The majority of the overhead comes from the handshake phase, specifically sending the X.509 server certificate (public key) and negotiating cipher suites, plus record header/tag overhead on each application packet.

**Q5: What does Shannon Entropy tell us in packet analysis?**  
**Ans:** Shannon entropy measures randomness on a scale from 0 to 8. Plaintext ASCII data has a lower entropy (~5.4), while encrypted ciphertext looks random and produces a much higher entropy (>7.3).
