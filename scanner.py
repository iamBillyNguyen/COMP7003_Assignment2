import argparse
import sys

from scapy.all import sniff

MAX_COUNT = 5

INTERFACE = ""
FILTER = ""
PORT = 80
COUNT = MAX_COUNT

# TODO 1 Add decimal representation for all arp fields
# TODO 2 Create a packet detail generator?
# TODO 3 Finish the rest of the filters
# TODO 4 Implement port filtering for ARP and TCP

def parse_arguments():
    global FILTER, PORT, COUNT, INTERFACE

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", type=str, required=True, help="Interface to scan for")
    parser.add_argument("-f", "--filter", type=str, required=True, help="Filter protocol to scan for. Supported protocols: arp, ipv4, tcp, udp.")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to scan for. Supported number of packets is between 1 to 5.")
    parser.add_argument("-p", "--port", type=int, help="Port to scan for") # Optional

    try:
        args = parser.parse_args()

    except SystemExit as e:
        parser.print_help()
        sys.exit(e.code)

    INTERFACE = args.interface.lower()
    FILTER = args.filter.lower()
    print("Interface: ", INTERFACE)
    print("Filter: ", FILTER)

    if args.port:
        PORT = args.port
    print("Port: ", PORT)

    if args.count:
        if MAX_COUNT >= args.count > 0:
            COUNT = args.count
        else:
            parser.print_help()
            sys.exit("Program only supports between 1 to 5 packets")
    print("Count: ", COUNT)

    if (FILTER != "tcp") and (FILTER != "udp") and (FILTER != "arp") and (FILTER != "ipv4"):
        parser.print_help()
        sys.exit("Program only supports TCP, UDP, ARP, IPv4")


def parse_ethernet(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

def parse_arp(hex_data):
    hardware_type = hex_data[28:32] # 2 bytes
    protocol_type = hex_data[32:36] # 2 bytes
    hardware_size = hex_data[36:38] # 1 byte
    protocol_size = hex_data[38:40] # 1 byte
    opcode = hex_data[40:44] # 2 bytes
    sender_mac = hex_data[44:56] # 6 bytes
    sender_ip = hex_data[56:64] # 4 bytes
    target_mac = hex_data[64:76] # 6 bytes
    target_ip = hex_data[76:84] # 4 bytes

    sender_mac_readable = convert_to_readable_mac(sender_mac)
    target_mac_readable = convert_to_readable_mac(target_mac)
    sender_ip_readable = convert_to_readable_ip(sender_ip)
    target_ip_readable = convert_to_readable_ip(target_ip)

    print(f"Hardware Type: {hardware_type}")
    print(f"Protocol Type: {protocol_type}")
    print(f"Hardware Size: {hardware_size}")
    print(f"Protocol Size: {protocol_size}")
    print(f"Opcode: {opcode}")
    print(f"Sender MAC: {sender_mac_readable}")
    print(f"Sender IP: {sender_ip_readable}")
    print(f"Target MAC: {target_mac_readable}")
    print(f"Target IP: {target_ip_readable}")

def parse_ipv4(hex_data):
    #TODO
    return 0

def parse_tcp(hex_data):
    #TODO
    return 0

def parse_udp(hex_data):
    #TODO
    return 0

def convert_to_readable_mac(mac_address):
    return ':'.join(mac_address[i:i+2] for i in range(0, 12, 2))

def convert_to_readable_ip(ip_address):
    readable_data = ""

    for i in range(0, 8, 2):
        readable_data += convert_hex_to_decimal(ip_address[i:i+2])
        if i != 6:
            readable_data += "."

    return readable_data

def convert_to_readable_binary(hex_data):
    binary_data = ""

    for i in range(0, len(hex_data), 1):
        binary_data += convert_hex_to_binary(hex_data[i:i + 1])

    return ' '.join(binary_data[i:i+4] for i in range(0, len(binary_data), 4))

def convert_hex_to_decimal(hex_data):
    return str(int(hex_data, 16))

def convert_hex_to_binary(hex_data):
    # print("To convert: {}".format(str(hex_data)))
    return "{0:04b}".format(int(hex_data, 16)) # 1 byte at a time

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")

    parse_ethernet(hex_data)

    if FILTER == "arp":
        print("Parsing ARP packet")
        parse_arp(hex_data)
    elif FILTER == "ipv4":
        print("Parsing IPv4 packet")
        parse_ipv4(hex_data)
    elif FILTER == "tcp":
        print("Parsing TCP packet")
        parse_tcp(hex_data)
    else:
        print("Parsing UDP packet")
        parse_udp(hex_data)

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    # Example usage (replace with actual interface and filter)
    # capture_packets('en0', 'tcp', 5)
    parse_arguments()
    capture_packets(INTERFACE, FILTER, COUNT)
    # test = "4000"
    # convert_to_readable_binary(test)
    # print("Result: {}".format(convert_to_readable_binary(test)))
