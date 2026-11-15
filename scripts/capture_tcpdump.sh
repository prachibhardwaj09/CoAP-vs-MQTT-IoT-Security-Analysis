#!/bin/bash
# Live packet capture script for local loopback interface
# Cyber Security Lab (7CIT4-22)

INTERFACE="lo0"
OUTPUT_FILE="pcaps/live_loopback_capture.pcap"
FILTER="port 1883 or port 8883 or port 5683 or port 5684"

echo "=========================================================="
echo " Starting live tcpdump capture on interface: $INTERFACE"
echo " Filter: $FILTER"
echo " Output: $OUTPUT_FILE"
echo " Press Ctrl+C to stop capture when transactions finish."
echo "=========================================================="

sudo tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE" "$FILTER"

