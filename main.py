import argparse
import sys
from scapy.all import sniff

from packet_parser import parse_ethernet

# Constraint
MAX_COUNT = 3

# User-defined Arguments
INTERFACE = ""
FILTER = ""
PORT = 0
COUNT = 1

# TODO 1. Separate functions into python files utils.py, packet_parser.py
# TODO 2. Create a function to handle hex_data gracefully get_field(hex_data, start, end) and return that size of hex_data

def parse_arguments():
    global FILTER, PORT, COUNT, INTERFACE

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", type=str, required=True, help="Interface to scan for")
    parser.add_argument("-f", "--filter", type=str, required=True, help="Filter protocol to scan for. Supported protocols: arp, tcp, udp.")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to scan for. Supported number of packets is between 1 to 3. (Default: 1)")
    parser.add_argument("-p", "--port", type=int, help="Port to scan for. (Default: unused)") # Optional

    try:
        args = parser.parse_args()

    except SystemExit as e:
        parser.print_help()
        sys.exit(e.code)

    INTERFACE = args.interface.lower()
    FILTER = args.filter.lower()
    print("Interface:\t", INTERFACE)

    if args.count:
        if MAX_COUNT >= args.count > 0:
            COUNT = args.count
        else:
            parser.print_help()
            sys.exit("Program only supports between 1 to 5 packets")
    print("Count:\t\t", COUNT)

    if (FILTER != "tcp") and (FILTER != "udp") and (FILTER != "arp"):
        parser.print_help()
        sys.exit("Program only supports TCP, UDP, and ARP filtering.")

    if args.port:
        PORT = args.port
        print("Port:\t\t", PORT)
        FILTER += " port " + str(PORT)
    print("Filter:\t\t", FILTER)

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"==================================")
    print(f"Captured Packet (Hex): {hex_data}")

    parse_ethernet(hex_data.upper())

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    packets = sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count, timeout=60)
    print(f"Done packet capture on {interface} with filter: {capture_filter}")

if __name__ == "__main__":
    parse_arguments()
    capture_packets(INTERFACE, FILTER, COUNT)
