#!/usr/bin/env python3
"""
Interactive CLI Dashboard: CoAP vs MQTT Security Analysis
Cyber Security Lab (7CIT4-22 / 7CS4-22) - Mini Project
Department of Computer Science & Engineering, SKIT Jaipur
"""

import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from certs.generate_certs import generate_certificates
from run_full_experiment import (
    run_experiment_1_mqtt_plaintext,
    run_experiment_2_mqtt_tls,
    run_experiment_3_coap_plaintext,
    run_experiment_4_coap_dtls,
    analyze_all_pcaps
)
from utils.packet_analyzer import PcapAnalyzer

PCAPS_DIR = os.path.join(BASE_DIR, "pcaps")

BANNER = """
================================================================================
       SWAMI KESHVANAND INSTITUTE OF TECHNOLOGY, MANAGEMENT & GRAMOTHAN
                   DEPARTMENT OF CSE / CSE (IoT) - JAIPUR
                     CYBER SECURITY LAB (7CIT4-22)
--------------------------------------------------------------------------------
   MINI PROJECT: CoAP vs MQTT Security & Overhead Analysis
   Reference: Exp 4 - Wireshark / tcpdump, TCP & UDP Client-Server Analysis
================================================================================
"""

def print_menu():
    print("\n[MAIN MENU]")
    print("  1. Run Full Experiment & Generate All 4 PCAPs (One-Click Automated)")
    print("  2. Run Individual Protocol Simulation:")
    print("       2a. Plaintext MQTT (TCP Port 1883)")
    print("       2b. Secure MQTT over TLS (TCP Port 8883)")
    print("       2c. Plaintext CoAP (UDP Port 5683)")
    print("       2d. Secure CoAP over DTLS (UDP Port 5684)")
    print("  3. Deep Packet Inspection (Check Cleartext Exposure in PCAPs)")
    print("  4. View Security & Overhead Comparison Table")
    print("  5. Wireshark Display Filters & Inspection Guide")
    print("  6. Regenerate X.509 TLS/DTLS Certificates")
    print("  7. Exit")
    print("--------------------------------------------------------------------------------")

def inspect_pcap_interactive():
    print("\n--- DEEP PACKET INSPECTION ---")
    pcap_files = [
        ("1", "01_mqtt_plaintext_tcp.pcap", "MQTT Plaintext (TCP)"),
        ("2", "02_mqtt_tls_tcp.pcap", "MQTT TLS (TCP)"),
        ("3", "03_coap_plaintext_udp.pcap", "CoAP Plaintext (UDP)"),
        ("4", "04_coap_dtls_udp.pcap", "CoAP DTLS (UDP)")
    ]
    for idx, fname, label in pcap_files:
        print(f"  [{idx}] {label} -> pcaps/{fname}")

    choice = input("\nSelect PCAP to inspect (1-4): ").strip()
    selected_file = None
    for idx, fname, label in pcap_files:
        if choice == idx or choice == fname:
            selected_file = os.path.join(PCAPS_DIR, fname)
            break

    if not selected_file or not os.path.exists(selected_file):
        print("[-] Invalid choice or PCAP file does not exist. Run option 1 first.")
        return

    analyzer = PcapAnalyzer(selected_file)
    summary = analyzer.get_summary(["temp", "password", "sensor", "api_key", "secret", "voltage", "token", "factory", "boiler"])

    print("\n" + "="*60)
    print(f" ANALYSIS REPORT: {os.path.basename(selected_file)}")
    print("="*60)
    print(f" Transport Layer        : {summary['transport']}")
    print(f" Total Captured Packets : {summary['packet_count']}")
    print(f" Total Captured Bytes   : {summary['total_bytes']} bytes")
    print(f" Application Data Bytes : {summary['app_bytes']} bytes")
    print(f" Shannon Entropy (0-8)  : {summary['entropy']} (High > 7 indicates strong encryption)")
    print(f" Encrypted Payload?     : {'YES' if summary['is_encrypted'] else 'NO (PLAINTEXT)'}")
    print(f" Exposed Plaintext Data : {', '.join(summary['exposed_keywords']) if summary['exposed_keywords'] else 'None detected'}")
    print(f" Security Status        : {summary['exposure_status']}")
    print("="*60)

def show_wireshark_guide():
    guide_path = os.path.join(BASE_DIR, "scripts", "wireshark_guide.md")
    if os.path.exists(guide_path):
        with open(guide_path, "r") as f:
            print("\n" + f.read())
    else:
        print("Guide not found.")

def main():
    print(BANNER)
    generate_certificates()

    while True:
        print_menu()
        choice = input("Enter choice (1-7): ").strip()

        if choice == "1":
            run_experiment_1_mqtt_plaintext()
            run_experiment_2_mqtt_tls()
            run_experiment_3_coap_plaintext()
            run_experiment_4_coap_dtls()
            analyze_all_pcaps()

        elif choice == "2a":
            run_experiment_1_mqtt_plaintext()
        elif choice == "2b":
            run_experiment_2_mqtt_tls()
        elif choice == "2c":
            run_experiment_3_coap_plaintext()
        elif choice == "2d":
            run_experiment_4_coap_dtls()

        elif choice == "3":
            inspect_pcap_interactive()

        elif choice == "4":
            summary_txt = os.path.join(PCAPS_DIR, "results_summary.txt")
            if os.path.exists(summary_txt):
                with open(summary_txt, "r") as f:
                    print("\n" + f.read())
            else:
                print("[*] Running analysis...")
                analyze_all_pcaps()

        elif choice == "5":
            show_wireshark_guide()

        elif choice == "6":
            generate_certificates(force=True)

        elif choice == "7":
            print("\nExiting. Good luck with your Cyber Security Lab Mini Project evaluation!")
            break
        else:
            print("[-] Invalid selection. Please enter a valid number (1-7).")

if __name__ == "__main__":
    main()

