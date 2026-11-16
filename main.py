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
    print("  2. Run Individual Protocol Simulation")
    print("  3. Deep Packet Inspection (Check Cleartext Exposure in PCAPs)")
    print("  4. View Security & Overhead Comparison Table")
    print("  5. Wireshark Display Filters & Inspection Guide")
    print("  6. Regenerate X.509 TLS/DTLS Certificates")
    print("  7. Exit")
    print("--------------------------------------------------------------------------------")

def run_individual_protocol():
    print("\n--- SELECT PROTOCOL SIMULATION ---")
    print("  1. Plaintext MQTT (TCP Port 1883)")
    print("  2. Secure MQTT over TLS (TCP Port 8883)")
    print("  3. Plaintext CoAP (UDP Port 5683)")
    print("  4. Secure CoAP over DTLS (UDP Port 5684)")
    print("  5. Back to Main Menu")
    
    sub = input("\nEnter choice (1-5): ").strip().lower()
    if sub in ["1", "a", "2a"]:
        run_experiment_1_mqtt_plaintext()
    elif sub in ["2", "b", "2b"]:
        run_experiment_2_mqtt_tls()
    elif sub in ["3", "c", "2c"]:
        run_experiment_3_coap_plaintext()
    elif sub in ["4", "d", "2d"]:
        run_experiment_4_coap_dtls()
    elif sub in ["5", "q", "back"]:
        return
    else:
        print("[-] Invalid selection.")

def inspect_pcap_interactive():
    print("\n--- DEEP PACKET INSPECTION ---")
    pcap_files = [
        ("1", "01_mqtt_plaintext_tcp.pcap", "MQTT Plaintext (TCP Port 1883)"),
        ("2", "02_mqtt_tls_tcp.pcap", "MQTT TLS (TCP Port 8883)"),
        ("3", "03_coap_plaintext_udp.pcap", "CoAP Plaintext (UDP Port 5683)"),
        ("4", "04_coap_dtls_udp.pcap", "CoAP DTLS (UDP Port 5684)")
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
        print("[-] PCAP file does not exist yet. Please run option 1 first to generate PCAPs.")
        return

    analyzer = PcapAnalyzer(selected_file)
    summary = analyzer.get_summary(["temp", "password", "sensor", "api_key", "secret", "voltage", "token", "factory", "boiler"])

    print("\n" + "="*65)
    print(f" DEEP PACKET INSPECTION: {os.path.basename(selected_file)}")
    print("="*65)
    print(f" Transport Layer        : {summary['transport']}")
    print(f" Total Captured Packets : {summary['packet_count']}")
    print(f" Total Captured Bytes   : {summary['total_bytes']} bytes")
    print(f" Application Data Bytes : {summary['app_bytes']} bytes")
    print(f" Shannon Entropy (0-8)  : {summary['entropy']} (High > 7 indicates strong encryption)")
    print(f" Encrypted Payload?     : {'YES' if summary['is_encrypted'] else 'NO (PLAINTEXT)'}")
    print(f" Exposed Plaintext Data : {', '.join(summary['exposed_keywords']) if summary['exposed_keywords'] else 'None detected'}")
    print(f" Security Status        : {summary['exposure_status']}")
    print("="*65)

def show_wireshark_guide():
    guide_path = os.path.join(BASE_DIR, "scripts", "wireshark_guide.md")
    if os.path.exists(guide_path):
        with open(guide_path, "r") as f:
            print("\n" + f.read())
    else:
        print("Guide file not found.")

def pause():
    input("\n[+] Press Enter to continue...")

def main():
    print(BANNER)
    generate_certificates()

    while True:
        print_menu()
        choice = input("Enter choice (1-7): ").strip().lower()

        if not choice:
            continue

        if choice == "1":
            run_experiment_1_mqtt_plaintext()
            run_experiment_2_mqtt_tls()
            run_experiment_3_coap_plaintext()
            run_experiment_4_coap_dtls()
            analyze_all_pcaps()
            pause()

        elif choice in ["2", "2a", "2b", "2c", "2d"]:
            if choice == "2":
                run_individual_protocol()
            elif choice == "2a":
                run_experiment_1_mqtt_plaintext()
            elif choice == "2b":
                run_experiment_2_mqtt_tls()
            elif choice == "2c":
                run_experiment_3_coap_plaintext()
            elif choice == "2d":
                run_experiment_4_coap_dtls()
            pause()

        elif choice == "3":
            inspect_pcap_interactive()
            pause()

        elif choice == "4":
            summary_txt = os.path.join(PCAPS_DIR, "results_summary.txt")
            if os.path.exists(summary_txt):
                with open(summary_txt, "r") as f:
                    print("\n" + f.read())
            else:
                print("[*] Results not found. Running analysis now...")
                analyze_all_pcaps()
            pause()

        elif choice == "5":
            show_wireshark_guide()
            pause()

        elif choice == "6":
            generate_certificates(force=True)
            pause()

        elif choice in ["7", "exit", "quit", "q"]:
            print("\nExiting dashboard. Good luck with your Cyber Security Lab Mini Project evaluation!")
            break
        else:
            print(f"[-] Invalid selection '{choice}'. Please enter a number between 1 and 7.")
            pause()

if __name__ == "__main__":
    main()
