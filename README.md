# Comparative Security and Overhead Analysis of IoT Protocols: Plaintext vs. Encrypted CoAP (UDP/DTLS) and MQTT (TCP/TLS)

**Cyber Security Lab (7CIT4-22 / 7CS4-22) — Mini Project**  
*Department of Computer Science & Engineering / CSE (IoT)*  
*Swami Keshvanand Institute of Technology, Management & Gramothan (SKIT), Jaipur*  
*Affiliated to Rajasthan Technical University (RTU), Kota*

---

## 1. Suggested Project Titles

| Option | Project Title | Tone / Best For |
|---|---|---|
| **Primary (Recommended)** | **Comparative Security and Overhead Analysis of IoT Protocols: Plaintext vs. Encrypted CoAP (UDP/DTLS) and MQTT (TCP/TLS)** | Academic, comprehensive, directly matches RTU syllabus objectives |
| **Option 2** | **IoT Protocol Vulnerability & Overhead Benchmarking: A Deep Packet Analysis of CoAP and MQTT using Wireshark & tcpdump** | Experimental focus emphasizing packet capture tools |
| **Option 3** | **Securing Constrained IoT Communications: Comparative Analysis of CoAP (UDP) and MQTT (TCP) under TLS/DTLS** | Concise & publication style |

---

## 2. Link to Syllabus: Experiment 4 Reference

* **RTU Syllabus Experiment 4 Title:**  
  *"Installation of Wireshark, tcpdump, etc. and observe data transferred in client-server communication using UDP/TCP and identify the TCP/UDP."*
* **How this Mini Project Extends Experiment 4:**
  1. **Transport Layer Foundation (TCP vs. UDP):** Exp 4 introduces basic packet sniffing and header identification. This mini project applies those exact concepts to the two dominant real-world IoT protocols: **MQTT** (which relies on connection-oriented TCP) and **CoAP** (which relies on lightweight, connectionless UDP).
  2. **Vulnerability Demonstration:** Uses Wireshark and tcpdump to prove that default client-server communications over both TCP (MQTT port 1883) and UDP (CoAP port 5683) transmit sensitive device credentials, topics, and telemetry in cleartext ASCII.
  3. **Cryptographic Hardening & Overhead Analysis:** Upgrades the transport layer to secure equivalents (**TLS 1.2/1.3** for TCP and **DTLS 1.2** for UDP) and empirically measures the network overhead (handshake bytes, packet count, entropy, and processing cost).

---

## 3. Language Selection & Justification

* **Chosen Language:** **Python 3**
* **Why Python is the Best Choice:**
  1. **Industry & Academic Standard:** Python is the premier language in cyber security research, packet inspection, and IoT security benchmarking.
  2. **Standard Library Capabilities:** Built-in `socket`, `ssl`, `struct`, and cryptographic utilities enable complete implementation of custom protocol framing, TLS/DTLS encapsulation, and raw `.pcap` generation without heavy third-party dependencies or external broker daemons.
  3. **Portability:** Runs effortlessly on macOS, Linux, and Windows systems commonly found in college lab environments.
  4. **Viva-Voce Ready:** Clean, readable code structure makes it easy for the student to explain the packet structure and socket flow during oral examination (Viva).

---

## 4. Project Architecture & File Organization

```
Wireshark/
├── certs/
│   ├── generate_certs.py       # Automated X.509 certificate generator (CA, Server, Client)
│   ├── ca.crt, ca.key          # Root Certificate Authority
│   ├── server.crt, server.key  # Server certificate with Subject Alternative Names (SAN)
│   └── client.crt, client.key  # Client certificate
├── protocols/
│   ├── mqtt.py                 # MQTT 3.1.1 packet builder & decoder (CONNECT, PUBLISH, etc.)
│   └── coap.py                 # RFC 7252 CoAP packet builder & decoder (Header, Options, URI)
├── servers/
│   ├── mqtt_broker.py          # Standalone MQTT broker (Plaintext port 1883 / TLS port 8883)
│   └── coap_server.py          # Standalone CoAP UDP server (Plaintext port 5683 / DTLS port 5684)
├── clients/
│   ├── mqtt_client.py          # MQTT client publishing simulated sensor telemetry & credentials
│   └── coap_client.py          # CoAP client sending POST requests with industrial telemetry
├── utils/
│   ├── pcap_writer.py          # Standard Libpcap (.pcap) file generator for Wireshark
│   └── packet_analyzer.py      # Automated entropy calculation & plaintext exposure scanner
├── pcaps/                      # Generated PCAP files ready for Wireshark inspection
│   ├── 01_mqtt_plaintext_tcp.pcap
│   ├── 02_mqtt_tls_tcp.pcap
│   ├── 03_coap_plaintext_udp.pcap
│   ├── 04_coap_dtls_udp.pcap
│   ├── results_summary.json
│   └── results_summary.txt
├── scripts/
│   ├── capture_tcpdump.sh      # Bash script to run live loopback tcpdump capture
│   └── wireshark_guide.md      # Detailed step-by-step Wireshark filters & screenshot checklist
├── main.py                     # Interactive CLI dashboard with menu options
├── run_full_experiment.py      # One-click execution script running all 4 scenarios & analysis
└── README.md                   # Complete documentation
```

---

## 5. How to Run the Working Project

### Quick Start (One-Click Execution)
Run the automated test suite to generate all 4 PCAP files and view the analysis table:

```bash
python3 run_full_experiment.py
```

### Interactive CLI Dashboard
Run the user-friendly terminal menu:

```bash
python3 main.py
```
From the interactive menu, you can:
- Execute all 4 scenarios.
- Run individual protocols.
- Perform deep packet inspection on any PCAP file.
- View real-time security alerts regarding cleartext credential exposure.
- Regenerate cryptographic certificates.

---

## 6. Empirical Results & Comparative Security Table

Below are the empirical metrics generated by the project analyzer across the four captured scenarios:

| Metric / Parameter | MQTT (Plain TCP) | MQTT (TLS / TCP) | CoAP (Plain UDP) | CoAP (DTLS / UDP) |
|---|---|---|---|---|
| **Transport Layer** | **TCP** | **TCP** | **UDP** | **UDP** |
| **Port Used** | 1883 | 8883 | 5683 | 5684 |
| **Security Layer** | None (Plaintext) | TLS 1.2 / 1.3 | None (Plaintext) | DTLS 1.2 (RFC 6347) |
| **Total Packets** | 12 | 15 | **2** | 11 |
| **Total Network Bytes** | 865 B | 2,812 B | **291 B** | 2,030 B |
| **Shannon Entropy (0–8)** | 5.42 (Plaintext) | **7.37 (Encrypted)** | 5.46 (Plaintext) | **7.47 (Encrypted)** |
| **Exposed Sensitive Data** | `admin_operator`, `LabSecretPassword@2026`, `factory/temperature`, `api_key` | **None (Encrypted)** | `/industrial/power_grid/voltage`, `override_token` | **None (Encrypted)** |
| **Security Status** | 🔴 **EXPOSED / VULNERABLE** | 🟢 **CONFIDENTIAL** | 🔴 **EXPOSED / VULNERABLE** | 🟢 **CONFIDENTIAL** |

### Key Analysis Takeaways:
1. **Cleartext Vulnerability:** Both Plaintext MQTT (TCP port 1883) and Plaintext CoAP (UDP port 5683) allow an eavesdropper using Wireshark or `tcpdump` to intercept usernames, passwords, device tokens, and sensor telemetry without breaking any encryption.
2. **Transport Layer Overhead (TCP vs. UDP):** CoAP over UDP requires **only 2 datagrams (291 bytes total)** for a complete request-response cycle, whereas MQTT over TCP requires **12 packets (865 bytes)** due to the mandatory TCP 3-way handshake (`SYN`, `SYN-ACK`, `ACK`), keep-alive, and connection teardown (`FIN-ACK`).
3. **Cryptographic Overhead:** Enabling TLS on MQTT increases network data by **+225% (2,812 bytes)**, while enabling DTLS on CoAP increases network data from 291 B to 2,030 B. The majority of this overhead (~1.5 KB to 2 KB) stems from exchanging X.509 public key certificates during the initial handshake.
4. **CoAP + DTLS Efficiency:** Even when fully encrypted, CoAP over DTLS consumes **~28% fewer bytes** than MQTT over TLS, making CoAP with DTLS the superior security choice for resource-constrained IoT devices running on batteries or low-bandwidth networks.

---

## 7. Wireshark & tcpdump Inspection Quick Guide

### Wireshark Display Filters
Open any generated `.pcap` in `pcaps/` and enter these filters in the top filter bar:

- **Plaintext MQTT:** `mqtt` or `tcp.port == 1883`
  - *Action:* Right-click packet -> **Follow** -> **TCP Stream** to see the unencrypted credentials and JSON payload.
- **TLS Encrypted MQTT:** `tls` or `tcp.port == 8883`
  - *Action:* Observe `Client Hello`, `Server Hello`, `Certificate`, and encrypted `Application Data`.
- **Plaintext CoAP:** `coap` or `udp.port == 5683`
  - *Action:* Inspect the 8-byte UDP header and expandable `Constrained Application Protocol` tree showing `Uri-Path` and cleartext payload.
- **DTLS Encrypted CoAP:** `dtls` or `udp.port == 5684`
  - *Action:* Observe the `Hello Verify Request` (DoS cookie exchange) and encrypted records.

### tcpdump Terminal Commands
```bash
# View plaintext MQTT credentials in terminal:
tcpdump -r pcaps/01_mqtt_plaintext_tcp.pcap -X

# View plaintext CoAP UDP datagram:
tcpdump -r pcaps/03_coap_plaintext_udp.pcap -X
```

---

## 8. Viva-Voce Questions & Answers (Exam Preparation)

**Q1: What is the primary architectural difference between CoAP and MQTT at the Transport Layer?**  
*Answer:* MQTT runs on **TCP** (connection-oriented, reliable transmission via 3-way handshake and retransmissions), using standard port 1883/8883. CoAP runs on **UDP** (connectionless, lightweight datagrams), using standard port 5683/5684.

**Q2: Why does MQTT expose credentials in plaintext by default?**  
*Answer:* The baseline MQTT specification transmits control packets (including `CONNECT` packets containing username and password fields) in raw binary/ASCII without encryption. Unless encapsulated inside TLS on port 8883, all data can be intercepted by anyone on the local network using Wireshark or tcpdump.

**Q3: How does DTLS differ from TLS when securing UDP traffic?**  
*Answer:* Standard TLS assumes an underlying reliable stream (TCP) and fails over UDP because UDP datagrams can be lost or reordered. DTLS (RFC 6347) adds sequence numbers, explicit epoch fields, and retransmission timers. Crucially, DTLS introduces a `Hello Verify Request` cookie exchange before allocating server memory, preventing attackers from using the server as a UDP amplification/reflection vector.

**Q4: In your project, what was the byte overhead when adding TLS and DTLS?**  
*Answer:* In our tests, Plaintext MQTT consumed 865 bytes, which jumped to 2,812 bytes under TLS (~3.2x increase). Plaintext CoAP consumed only 291 bytes across 2 packets, which rose to 2,030 bytes under DTLS. Most of this initial overhead is due to the X.509 public key certificate exchange.

**Q5: What is Shannon Entropy and how does it prove encryption in Wireshark?**  
*Answer:* Shannon entropy measures the degree of randomness in a byte sequence on a scale from 0 to 8. Plaintext human-readable text and JSON have low entropy (~4.5 to 5.5). Strong cryptographic ciphertexts (AES-GCM, ChaCha20) exhibit near-maximal entropy (~7.3 to 7.9). In our analyzer, the jump in entropy from 5.4 to >7.3 quantitatively proves that encryption effectively scrambled the plaintext.

