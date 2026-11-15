#!/usr/bin/env python3
"""
Certificate Generator for TLS/DTLS Testing
Generates self-signed CA, Server, and Client X.509 certificates for localhost testing.
"""

import os
import subprocess
import sys

CERTS_DIR = os.path.dirname(os.path.abspath(__file__))

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Command failed: {cmd}")
        print(f"    Error: {result.stderr.strip()}")
        return False
    return True

def generate_certificates(force=False):
    ca_crt = os.path.join(CERTS_DIR, "ca.crt")
    ca_key = os.path.join(CERTS_DIR, "ca.key")
    srv_crt = os.path.join(CERTS_DIR, "server.crt")
    srv_key = os.path.join(CERTS_DIR, "server.key")
    cli_crt = os.path.join(CERTS_DIR, "client.crt")
    cli_key = os.path.join(CERTS_DIR, "client.key")

    if not force and os.path.exists(srv_crt) and os.path.exists(srv_key):
        print("[+] Certificates already exist in certs/. Skipping generation.")
        return True

    print("[*] Generating X.509 certificates for TLS/DTLS...")

    # 1. OpenSSL Config with SAN
    cnf_path = os.path.join(CERTS_DIR, "openssl.cnf")
    with open(cnf_path, "w") as f:
        f.write("""
[ req ]
default_bits        = 2048
default_md          = sha256
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca
string_mask         = utf8only

[ req_distinguished_name ]
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_default              = localhost

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
""")

    # 2. CA Key & Cert
    print("    -> Generating Root CA...")
    if not run_cmd(f"openssl req -x509 -new -nodes -newkey rsa:2048 -keyout '{ca_key}' -out '{ca_crt}' -days 365 -subj '/C=IN/ST=Rajasthan/L=Jaipur/O=SKIT/OU=CyberSecurityLab/CN=SKIT-IoT-RootCA' -config '{cnf_path}'"):
        return False

    # 3. Server Key & CSR
    print("    -> Generating Server Certificate (localhost / 127.0.0.1)...")
    srv_csr = os.path.join(CERTS_DIR, "server.csr")
    if not run_cmd(f"openssl req -new -nodes -newkey rsa:2048 -keyout '{srv_key}' -out '{srv_csr}' -subj '/C=IN/ST=Rajasthan/L=Jaipur/O=SKIT/OU=IoT/CN=localhost' -config '{cnf_path}'"):
        return False

    # 4. Sign Server CSR with CA
    ext_file = os.path.join(CERTS_DIR, "server_ext.cnf")
    with open(ext_file, "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\n")

    if not run_cmd(f"openssl x509 -req -in '{srv_csr}' -CA '{ca_crt}' -CAkey '{ca_key}' -CAcreateserial -out '{srv_crt}' -days 365 -sha256 -extfile '{ext_file}'"):
        return False

    # 5. Client Key & Cert (for client authentication / mTLS if needed)
    print("    -> Generating Client Certificate...")
    cli_csr = os.path.join(CERTS_DIR, "client.csr")
    if not run_cmd(f"openssl req -new -nodes -newkey rsa:2048 -keyout '{cli_key}' -out '{cli_csr}' -subj '/C=IN/ST=Rajasthan/L=Jaipur/O=SKIT/OU=IoT-Sensor/CN=sensor-client' -config '{cnf_path}'"):
        return False

    if not run_cmd(f"openssl x509 -req -in '{cli_csr}' -CA '{ca_crt}' -CAkey '{ca_key}' -CAcreateserial -out '{cli_crt}' -days 365 -sha256"):
        return False

    # Clean temporary CSR and config files
    for tmp in [cnf_path, srv_csr, cli_csr, ext_file, os.path.join(CERTS_DIR, "ca.srl")]:
        if os.path.exists(tmp):
            os.remove(tmp)

    print("[+] All TLS/DTLS certificates generated successfully!")
    return True

if __name__ == "__main__":
    force_gen = "--force" in sys.argv
    generate_certificates(force=force_gen)

