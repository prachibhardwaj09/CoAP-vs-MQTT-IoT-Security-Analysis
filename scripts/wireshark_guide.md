# Wireshark & tcpdump Inspection Guide
## Cyber Security Lab (7CIT4-22) — Exp 4 Extended Project

This guide provides step-by-step instructions for opening the generated `.pcap` files in Wireshark and tcpdump, applying display filters, and capturing evidence screenshots for your lab evaluation.

---

### 1. Generated PCAP Files Summary

All capture files are located in the `pcaps/` folder:
- `pcaps/01_mqtt_plaintext_tcp.pcap` — Plaintext MQTT over TCP (Port 1883)
- `pcaps/02_mqtt_tls_tcp.pcap`       — Secure MQTT over TLS/TCP (Port 8883)
- `pcaps/03_coap_plaintext_udp.pcap` — Plaintext CoAP over UDP (Port 5683)
- `pcaps/04_coap_dtls_udp.pcap`      — Secure CoAP over DTLS/UDP (Port 5684)

---

### 2. Wireshark Display Filters & Inspection

#### A. Scenario 1: Plaintext MQTT (TCP Port 1883)
1. Launch Wireshark and open `pcaps/01_mqtt_plaintext_tcp.pcap`.
2. Apply Display Filter:
   ```text
   mqtt
   ```
   *(Or filter by transport layer: `tcp.port == 1883`)*
3. **What to Observe**:
   - **TCP 3-Way Handshake**: Notice packets 1, 2, and 3 (`[SYN]`, `[SYN, ACK]`, `[ACK]`).
   - **MQTT CONNECT**: Click on packet 4. In the Packet Details pane, expand `MQ Telemetry Transport Protocol` -> `Header Flags` -> `User Name: admin_operator` and `Password: LabSecretPassword@2026`.
   - **MQTT PUBLISH**: Click on packet 6. Expand `Message`: Notice the topic `skit/iot/factory/temperature` and the payload `{"sensor":"temp_sensor_01","temperature":29.4,...}`.
4. **Follow Stream**: Right-click packet 6 -> **Follow** -> **TCP Stream**. Everything is readable in cleartext ASCII!
5. **Screenshot 1**: Take a screenshot of the cleartext MQTT credentials and JSON payload.

---

#### B. Scenario 2: Secure MQTT over TLS (TCP Port 8883)
1. Open `pcaps/02_mqtt_tls_tcp.pcap`.
2. Apply Display Filter:
   ```text
   tls
   ```
   *(Or filter by port: `tcp.port == 8883`)*
3. **What to Observe**:
   - **TLS Handshake**:
     - `Client Hello`: Cryptographic cipher suites offered by client.
     - `Server Hello`: Cipher suite selected (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
     - `Certificate`: X.509 certificate exchange.
     - `Server Key Exchange`, `Client Key Exchange`, `Change Cipher Spec`.
   - **Encrypted Application Data**: All MQTT packets are wrapped inside TLS records (`ContentType: Application Data (23)`).
4. **Follow Stream**: Right-click an Application Data packet -> **Follow** -> **TCP Stream**. Observe that all bytes are pseudorandom ciphertext. An attacker sniffing the wire gets zero information!
5. **Screenshot 2**: Take a screenshot of the TLS Handshake and Application Data records.

---

#### C. Scenario 3: Plaintext CoAP (UDP Port 5683)
1. Open `pcaps/03_coap_plaintext_udp.pcap`.
2. Apply Display Filter:
   ```text
   coap
   ```
   *(Or filter by port: `udp.port == 5683`)*
3. **What to Observe**:
   - **Transport Layer**: Expand `User Datagram Protocol (UDP)`. Note header length is strictly **8 bytes**! There is **no 3-way handshake**; transmission begins immediately.
   - **CoAP Header**: Expand `Constrained Application Protocol`.
     - `Type: Confirmable (0)`
     - `Code: POST (2)`
     - `Message ID: 0x3a4b`
   - **CoAP Options**: Notice `Opt Name: Uri-Path` = `industrial`, `power_grid`, `voltage`.
   - **CoAP Payload**: The JSON string containing `grid_substation` and `override_token` is exposed in cleartext!
4. **Screenshot 3**: Take a screenshot showing the 8-byte UDP header, CoAP Uri-Path, and cleartext payload.

---

#### D. Scenario 4: Secure CoAP over DTLS (UDP Port 5684)
1. Open `pcaps/04_coap_dtls_udp.pcap`.
2. Apply Display Filter:
   ```text
   dtls
   ```
   *(Or filter by port: `udp.port == 5684`)*
3. **What to Observe**:
   - **DTLS Handshake (RFC 6347)**:
     - Notice the `Hello Verify Request` containing a server cookie (crucial defense mechanism in DTLS to prevent UDP denial-of-service and amplification attacks).
     - Second `Client Hello` presenting the cookie.
     - `Server Hello`, `Certificate`, and key exchange.
   - **DTLS Encrypted Application Data**:
     - Records with `ContentType: Application Data (23)`, `Epoch: 1`.
     - The CoAP headers, URI path, and payload are 100% encrypted.
4. **Screenshot 4**: Take a screenshot of the DTLS Hello Verify Request and Encrypted Application Data.

---

### 3. Wireshark Statistical Comparison (For Report Graphs/Tables)

In Wireshark:
1. Open any capture file.
2. Go to top menu: **Statistics** -> **Protocol Hierarchy**.
   - View percentage of packets in TCP vs UDP, and Plaintext vs TLS/DTLS.
3. Go to **Statistics** -> **Summary** (or **Capture File Properties**):
   - Record the exact average packet size, byte counts, and duration.

---

### 4. Command-Line tcpdump Inspection

You can inspect the PCAP files directly in your terminal without opening a GUI:

```bash
# 1. Inspect Plaintext MQTT ASCII payload
tcpdump -r pcaps/01_mqtt_plaintext_tcp.pcap -X

# 2. Inspect Plaintext CoAP UDP datagrams
tcpdump -r pcaps/03_coap_plaintext_udp.pcap -X

# 3. View packet summary with line numbers
tcpdump -r pcaps/02_mqtt_tls_tcp.pcap -tnn

# 4. Filter only port 1883 or 5683
tcpdump -r pcaps/01_mqtt_plaintext_tcp.pcap "tcp port 1883" -A
```

---

### 5. Live Capture with tcpdump (Optional Lab Demo)

If demonstrating live capture during viva:
```bash
# Capture loopback traffic while running client/server
sudo tcpdump -i lo0 -w live_capture.pcap "port 1883 or port 8883 or port 5683 or port 5684"
```

