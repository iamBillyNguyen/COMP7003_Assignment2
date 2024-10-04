import argparse
import sys
from scapy.all import sniff

# Constraint
MAX_COUNT = 3

# EtherType
ARP = "0806"
IPV4 = "0800"

# Protocol
TCP = "6"
UDP = "17"

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

def parse_ethernet(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))

    # print(f"Destination MAC:\n\tHex Value: {dest_mac}\n\tReadable Value: {dest_mac_readable}")
    display_packet_field("Destination MAC", dest_mac, dest_mac_readable)
    # print(f"Source MAC:\n\tHex Value: {source_mac}\n\tReadable Value: {source_mac_readable}")
    display_packet_field("Source MAC", source_mac, source_mac_readable)
    # print(f"EtherType:\n\tHex Value: {ether_type}")
    display_packet_field("EtherType", ether_type, "")

    print(f"--------------------------")
    if ether_type.upper() == ARP:
        print("Packet type: ARP")
        parse_arp(hex_data)
    elif ether_type == IPV4:
        print("Packet type: IPv4")
        parse_ipv4(hex_data)
    else:
        sys.exit("Program only supports ARP, and IPv4 EtherType. Try again.")

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

    # print(f"Hardware Type: \n\tHex Value: {hardware_type}\n\tDecimal Value: {convert_hex_to_decimal(hardware_type)}")
    display_packet_field("Hardware Type", hardware_type, convert_hex_to_decimal(hardware_type))
    # print(f"Protocol Type: \n\tHex Value: {protocol_type}\n\tDecimal Value: {convert_hex_to_decimal(protocol_type)}")
    display_packet_field("Protocol Type", protocol_type, convert_hex_to_decimal(protocol_type))
    # print(f"Hardware Size: \n\tHex Value: {hardware_size}\n\tDecimal Value: {convert_hex_to_decimal(hardware_size)}")
    display_packet_field("Hardware Size", hardware_size, convert_hex_to_decimal(hardware_size))
    # print(f"Protocol Size: \n\tHex Value: {protocol_size}\n\tDecimal Value: {convert_hex_to_decimal(protocol_size)}")
    display_packet_field("Protocol Size", protocol_size, convert_hex_to_decimal(protocol_size))
    # print(f"Opcode: \n\tHex Value: {opcode}\n\tDecimal Value: {convert_hex_to_decimal(opcode)}")
    display_packet_field("Opcode", opcode, convert_hex_to_decimal(opcode))
    # print(f"Sender MAC: \n\tHex Value: {sender_mac}\n\tReadable Value: {sender_mac_readable}")
    display_packet_field("Sender MAC", sender_mac, sender_mac_readable)
    # print(f"Sender IP: \n\tHex Value: {sender_ip}\n\tReadable Value: {sender_ip_readable}")
    display_packet_field("Sender IP", sender_ip, sender_ip_readable)
    # print(f"Target MAC: \n\tHex Value: {target_mac}\n\tReadable Value: {target_mac_readable}")
    display_packet_field("Target MAC", target_mac, target_mac_readable)
    # print(f"Target IP: \n\tHex Value: {target_ip_readable}\n\tReadable Value: {target_ip_readable}")
    display_packet_field("Target IP", target_ip, target_ip_readable)

def parse_ipv4(hex_data):
    global TCP, UDP
    version = hex_data[28:29]
    header_length = hex_data[29:30]
    type_of_service = hex_data[30:32]
    total_length = hex_data[32:36]
    identification = hex_data[36:40]
    flags_and_offset = hex_data[40:44]
    time_to_live = hex_data[44:46]
    protocol = hex_data[46:48]
    header_checksum = hex_data[48:52]
    source_ip = hex_data[52:60]
    destination_ip = hex_data[60:68]

    flags_and_offset_readable = convert_to_readable_binary(flags_and_offset)
    reserved = flags_and_offset_readable[0]
    not_fragment = flags_and_offset_readable[1]
    more_fragment = flags_and_offset_readable[2]
    offset_readable = flags_and_offset_readable[3:len(flags_and_offset_readable)]
    protocol_decimal = convert_hex_to_decimal(protocol)
    source_ip_readable = convert_to_readable_ip(source_ip)
    destination_ip_readable = convert_to_readable_ip(destination_ip)

    # print(f"Version:\n\tHex Value: {version}\n\tDecimal Value: {convert_hex_to_decimal(version)}")
    display_packet_field("Version", version, convert_hex_to_decimal(version))
    # print(f"Header Length:\n\tHex Value: {header_length}\n\tDecimal Value: {convert_hex_to_decimal(header_length)}")
    display_packet_field("Header Length", header_length, convert_hex_to_decimal(header_length))
    # print(f"Type Of Service:\n\tHex Value: {type_of_service}\n\tDecimal Value: {convert_hex_to_decimal(type_of_service)}")
    display_packet_field("Type Of Service", type_of_service, convert_hex_to_decimal(type_of_service))
    # print(f"Total Length:\n\tHex Value: {total_length}\n\tDecimal Value: {convert_hex_to_decimal(total_length)}")
    display_packet_field("Total Length", total_length, convert_hex_to_decimal(total_length))
    # print(f"Identification:\n\tHex Value: {identification}\n\tDecimal Value: {convert_hex_to_decimal(identification)}")
    display_packet_field("Identification", identification, convert_hex_to_decimal(identification))
    # print(f"Flags + Offset:\n\tHex Value: {flags_and_offset}\n\tBinary Value: {flags_and_offset_readable}\n\tDecimal Value: {convert_hex_to_decimal(flags_and_offset)}")
    display_packet_field_for_flags("Flags + Offset", flags_and_offset, convert_hex_to_decimal(flags_and_offset), flags_and_offset_readable)
    # print(f"- Reserved:\n\tHex Value: {reserved}\n\tDecimal Value: {convert_hex_to_decimal(reserved)}")
    display_packet_field("- Reserved", reserved, convert_hex_to_decimal(reserved))
    # print(f"- Don't Fragment:\n\tHex Value: {not_fragment}\n\tDecimal Value: {convert_hex_to_decimal(not_fragment)}")
    display_packet_field("- Don't Fragment", not_fragment, convert_hex_to_decimal(not_fragment))
    # print(f"- More Fragment:\n\tHex Value: {more_fragment}\n\tDecimal Value: {convert_hex_to_decimal(more_fragment)}")
    display_packet_field("- More Fragment", more_fragment, convert_hex_to_decimal(more_fragment))
    # print(f"Fragment Offset:\n\tHex Value: {flags_and_offset[1:4]}\n\tBinary Value: {offset_readable}\n\tDecimal Value: {convert_hex_to_decimal(flags_and_offset[1:4])}")
    display_packet_field_for_flags("Fragment Offset", flags_and_offset[1:4], convert_hex_to_decimal(flags_and_offset[1:4]), offset_readable)
    # print(f"Time To Live:\n\tHex Value: {time_to_live}\n\tDecimal Value: {convert_hex_to_decimal(time_to_live)}")
    display_packet_field("Time To Live", time_to_live, convert_hex_to_decimal(time_to_live))
    # print(f"Protocol:\n\tHex Value: {protocol}\n\tDecimal Value: {protocol_decimal}")
    display_packet_field("Protocol", protocol, protocol_decimal)
    # print(f"Checksum:\n\tHex Value: {header_checksum}\n\tDecimal Value: {convert_hex_to_decimal(header_checksum)}")
    display_packet_field("Checksum", header_checksum, convert_hex_to_decimal(header_checksum))
    # print(f"Source IP:\n\tHex Value: {source_ip}\n\tReadable Value: {source_ip_readable}")
    display_packet_field("Source IP", source_ip, source_ip_readable)
    # print(f"Destination IP:\n\tHex Value: {destination_ip}\n\tReadable Value: {destination_ip_readable}")
    display_packet_field("Destination IP", destination_ip, destination_ip_readable)

    print(f"--------------------------")
    if protocol_decimal == TCP:
        print(f"Packet type: TCP")
        parse_tcp(hex_data)
    elif protocol_decimal == UDP:
        print(f"Packet type: UDP")
        parse_udp(hex_data)
    else:
        sys.exit("Program only supports TCP or UDP protocol. Try again.")

def parse_tcp(hex_data):
    hex_data = hex_data.lower()
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    sequence_number = hex_data[76:84]
    acknowledgement_number = hex_data[84:92]
    data_offset = hex_data[92:93]
    reserved_and_flags = hex_data[93:96]
    window_size = hex_data[96:100]
    checksum = hex_data[100:104]
    urgent_pointer = hex_data[104:108]
    options = hex_data[108:132]
    data = hex_data[132:len(hex_data)]

    reserved_and_flag_readable = convert_to_readable_binary(reserved_and_flags)
    reserved_readable = reserved_and_flag_readable[0:3]

    flag_readable = reserved_and_flag_readable[3:len(reserved_and_flag_readable)]
    no_space_flag = flag_readable.replace(" ", "")
    cwr = no_space_flag[1]
    ece = no_space_flag[2]
    urg = no_space_flag[3]
    ack = no_space_flag[4]
    psh = no_space_flag[5]
    res = no_space_flag[6]
    syn = no_space_flag[7]
    fin = no_space_flag[8]

    # print(f"Source Port:\n\tHex Value: {source_port}\n\tDecimal Value: {convert_hex_to_decimal(source_port)}")
    display_packet_field("Source Port", source_port, convert_hex_to_decimal(source_port))
    # print(f"Destination Port:\n\tHex Value: {destination_port}\n\tDecimal Value: {convert_hex_to_decimal(destination_port)}")
    display_packet_field("Destination Port", destination_port, convert_hex_to_decimal(destination_port))
    # print(f"Sequence Number:\n\tHex Value: {sequence_number}\n\tDecimal Value: {convert_hex_to_decimal(sequence_number)}")
    display_packet_field("Sequence Number", sequence_number, convert_hex_to_decimal(sequence_number))
    # print(f"Acknowledgement Number:\n\tHex Value: {acknowledgement_number}\n\tDecimal Value: {convert_hex_to_decimal(acknowledgement_number)}")
    display_packet_field("Acknowledgement Number", acknowledgement_number, convert_hex_to_decimal(acknowledgement_number))
    # print(f"Data offset:\n\tHex Value: {data_offset}\n\tDecimal Value: {convert_hex_to_decimal(data_offset)}")
    display_packet_field("Data Offset", data_offset, convert_hex_to_decimal(data_offset))
    # print(f"Reserved + Flags:\n\tHex Value: {reserved_and_flags}\n\tBinary Value: {reserved_and_flag_readable}\n\tDecimal Value: {convert_hex_to_decimal(reserved_and_flags)}")
    display_packet_field_for_flags("Reserved + Flags", reserved_and_flags, convert_hex_to_decimal(reserved_and_flags), reserved_and_flag_readable)
    # print(f"Reserved:\n\tHex Value: {reserved_and_flags[0]}\n\tBinary Value: {reserved_readable}\n\tDecimal Value: {convert_hex_to_decimal(reserved_and_flags[0])}")
    display_packet_field_for_flags("- Reserved", reserved_and_flags[0], convert_hex_to_decimal(reserved_and_flags[0]), reserved_readable)
    # print(f"- CWR:\n\tHex Value: {cwr}\n\tDecimal Value: {convert_hex_to_decimal(cwr)}")
    display_packet_field("- CWR", cwr, convert_hex_to_decimal(cwr))
    # print(f"- ECE:\n\tHex Value: {ece}\n\tDecimal Value: {convert_hex_to_decimal(ece)}")
    display_packet_field("- ECE", ece, convert_hex_to_decimal(ece))
    # print(f"- URG:\n\tHex Value: {urg}\n\tDecimal Value: {convert_hex_to_decimal(urg)}")
    display_packet_field("- URG", urg, convert_hex_to_decimal(urg))
    # print(f"- ACK:\n\tHex Value: {ack}\n\tDecimal Value: {convert_hex_to_decimal(ack)}")
    display_packet_field("- ACK", ack, convert_hex_to_decimal(ack))
    # print(f"- PSH:\n\tHex Value: {psh}\n\tDecimal Value: {convert_hex_to_decimal(psh)}")
    display_packet_field("- PSH", psh, convert_hex_to_decimal(psh))
    # print(f"- RES:\n\tHex Value: {res}\n\tDecimal Value: {convert_hex_to_decimal(res)}")
    display_packet_field("- RES", res, convert_hex_to_decimal(res))
    # print(f"- SYN:\n\tHex Value: {syn}\n\tDecimal Value: {convert_hex_to_decimal(syn)}")
    display_packet_field("- SYN", syn, convert_hex_to_decimal(syn))
    # print(f"- FIN:\n\tHex Value: {fin}\n\tDecimal Value: {convert_hex_to_decimal(fin)}")
    display_packet_field("- FIN", fin, convert_hex_to_decimal(fin))
    # print(f"Window Size:\n\tHex Value: {window_size}\n\tDecimal Value: {convert_hex_to_decimal(window_size)}")
    display_packet_field("Window Size", window_size, convert_hex_to_decimal(window_size))
    # print(f"Checksum:\n\tHex Value: {checksum}\n\tDecimal Value: {convert_hex_to_decimal(checksum)}")
    display_packet_field("Checksum", checksum, convert_hex_to_decimal(checksum))
    # print(f"Urgent Pointer:\n\tHex Value: {urgent_pointer}\n\tDecimal Value: {convert_hex_to_decimal(urgent_pointer)}")
    display_packet_field("Urgent Pointer", urgent_pointer, convert_hex_to_decimal(urgent_pointer))
    # print(f"Options:\n\tHex Value: {options}")
    display_packet_field("Options", options, "")
    # print(f"Data:\n\tHex Value: {data}\n\tReadable Value: {convert_hex_to_text(data)}")
    display_packet_field("Data", data, convert_hex_to_text(data))

def parse_udp(hex_data):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    length = hex_data[76:80]
    checksum = hex_data[80:84]

    # print(f"Source Port:\n\tHex Value: {source_port}\n\tDecimal Value: {convert_hex_to_decimal(source_port)}")
    display_packet_field("Source Port", source_port, convert_hex_to_decimal(source_port))
    # print(f"Destination Port:\n\tHex Value: {destination_port}\n\tDecimal Value: {convert_hex_to_decimal(destination_port)}")
    display_packet_field("Destination Port", destination_port, convert_hex_to_decimal(destination_port))
    # print(f"Length:\n\tHex Value: {length}\n\tDecimal Value: {convert_hex_to_decimal(length)}")
    display_packet_field("Length", length, convert_hex_to_decimal(length))
    # print(f"Checksum:\n\tHex Value: {checksum}\n\tDecimal Value: {convert_hex_to_decimal(checksum)}")
    display_packet_field("Checksum", checksum, convert_hex_to_decimal(checksum))

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
    return "{0:04b}".format(int(hex_data, 16)) # 1 byte at a time

def convert_hex_to_text(hex_data):
    return ''.join([chr(int(hex_data[i:i+2], 16)) for i in range(0, len(hex_data), 2)])

def display_packet_field(field_name, hex_data, decimal_data):
    print(f"{field_name}:\n\tHex Value: {hex_data}\n\tReadable Value: {decimal_data}")

def display_packet_field_for_flags(field_name, hex_data, decimal_data, binary_data):
    print(f"{field_name}:\n\tHex Value: {hex_data}\n\tBinary Value: {binary_data}\n\tReadable Value: {decimal_data}")

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
