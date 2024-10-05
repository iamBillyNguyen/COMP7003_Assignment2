import sys
from pkgutil import get_data

from utils import *

# EtherType
ARP = "0806"
IPV4 = "0800"

# Protocol
TCP = "6"
UDP = "17"

def parse_ethernet(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac, hex_data = get_data_field(hex_data, 12)
    source_mac, hex_data = get_data_field(hex_data, 12)
    ether_type, hex_data = get_data_field(hex_data, 4)

    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i + 2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i + 2] for i in range(0, 12, 2))

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
    hardware_type, hex_data   = get_data_field(hex_data, 4) # 2 bytes
    protocol_type, hex_data   = get_data_field(hex_data, 4) # 2 bytes
    hardware_size, hex_data   = get_data_field(hex_data, 2) # 1 byte
    protocol_size, hex_data   = get_data_field(hex_data, 2) # 1 byte
    opcode, hex_data          = get_data_field(hex_data, 4) # 2 bytes
    sender_mac, hex_data      = get_data_field(hex_data, 12) # 6 bytes
    sender_ip, hex_data       = get_data_field(hex_data, 8) # 4 bytes
    target_mac, hex_data      = get_data_field(hex_data, 12) # 6 bytes
    target_ip, hex_data       = get_data_field(hex_data, 8) # 4 bytes

    sender_mac_readable = convert_to_readable_mac(sender_mac)
    target_mac_readable = convert_to_readable_mac(target_mac)
    sender_ip_readable  = convert_to_readable_ip(sender_ip)
    target_ip_readable  = convert_to_readable_ip(target_ip)

    display_packet_field("Hardware Type", hardware_type, convert_hex_to_decimal(hardware_type))
    display_packet_field("Protocol Type", protocol_type, convert_hex_to_decimal(protocol_type))
    display_packet_field("Hardware Size", hardware_size, convert_hex_to_decimal(hardware_size))
    display_packet_field("Protocol Size", protocol_size, convert_hex_to_decimal(protocol_size))
    display_packet_field("Opcode", opcode, convert_hex_to_decimal(opcode))
    display_packet_field("Sender MAC", sender_mac, sender_mac_readable)
    display_packet_field("Sender IP", sender_ip, sender_ip_readable)
    display_packet_field("Target MAC", target_mac, target_mac_readable)
    display_packet_field("Target IP", target_ip, target_ip_readable)

def parse_ipv4(hex_data):
    global TCP, UDP

    version, hex_data             = get_data_field(hex_data, 1) # 4 bits
    header_length, hex_data       = get_data_field(hex_data, 1) # 4 bits
    type_of_service, hex_data     = get_data_field(hex_data, 2) # 8 bits
    total_length, hex_data        = get_data_field(hex_data, 4) # 16 bits
    identification, hex_data      = get_data_field(hex_data, 4) # 16 bits
    flags_and_offset, hex_data    = get_data_field(hex_data, 4)# 3 bits and 13 bits
    time_to_live, hex_data        = get_data_field(hex_data, 2)# 8 bits
    protocol, hex_data            = get_data_field(hex_data, 2)# 8 bits
    header_checksum, hex_data     = get_data_field(hex_data, 4) # 16 bits
    source_ip, hex_data           = get_data_field(hex_data, 8)# 32 bits
    destination_ip, hex_data      = get_data_field(hex_data, 8) # 32 bits

    flags_and_offset_readable   = convert_to_readable_binary(flags_and_offset)
    reserved                    = flags_and_offset_readable[0]
    not_fragment                = flags_and_offset_readable[1]
    more_fragment               = flags_and_offset_readable[2]
    offset_readable             = flags_and_offset_readable[3:]
    protocol_decimal            = convert_hex_to_decimal(protocol)
    source_ip_readable          = convert_to_readable_ip(source_ip)
    destination_ip_readable     = convert_to_readable_ip(destination_ip)

    display_packet_field("Version", version, convert_hex_to_decimal(version))
    display_packet_field("Header Length", header_length, convert_hex_to_decimal(header_length))
    display_packet_field("Type Of Service", type_of_service, convert_hex_to_decimal(type_of_service))
    display_packet_field("Total Length", total_length, convert_hex_to_decimal(total_length))
    display_packet_field("Identification", identification, convert_hex_to_decimal(identification))
    display_packet_field_for_flags("Flags + Offset", flags_and_offset, convert_hex_to_decimal(flags_and_offset), flags_and_offset_readable)
    display_packet_field("- Reserved", reserved, convert_hex_to_decimal(reserved))
    display_packet_field("- Don't Fragment", not_fragment, convert_hex_to_decimal(not_fragment))
    display_packet_field("- More Fragment", more_fragment, convert_hex_to_decimal(more_fragment))
    display_packet_field_for_flags("Fragment Offset", flags_and_offset[1:4], convert_hex_to_decimal(flags_and_offset[1:4]), offset_readable)
    display_packet_field("Time To Live", time_to_live, convert_hex_to_decimal(time_to_live))
    display_packet_field("Protocol", protocol, protocol_decimal)
    display_packet_field("Checksum", header_checksum, convert_hex_to_decimal(header_checksum))
    display_packet_field("Source IP", source_ip, source_ip_readable)
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
    hex_data                            = hex_data.lower()
    source_port, hex_data               = get_data_field(hex_data, 4) # 16 bits
    destination_port, hex_data          = get_data_field(hex_data, 4) # 16 bits
    sequence_number, hex_data           = get_data_field(hex_data, 8) # 32 bits
    acknowledgement_number, hex_data    = get_data_field(hex_data, 8) # 32 bits
    data_offset, hex_data               = get_data_field(hex_data, 1) # 4 bits
    reserved_and_flags, hex_data        = get_data_field(hex_data, 3) # 3 bits and 9 bits
    window_size, hex_data               = get_data_field(hex_data, 4) # 16 bits
    checksum, hex_data                  = get_data_field(hex_data, 4) # 16 bits
    urgent_pointer, hex_data            = get_data_field(hex_data, 4) # 16 bits
    options, hex_data                   = get_data_field(hex_data, 24) # 12 bytes
    data, hex_data                      = get_data_field(hex_data, len(hex_data)) # the rest

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

    display_packet_field("Source Port", source_port, convert_hex_to_decimal(source_port))
    display_packet_field("Destination Port", destination_port, convert_hex_to_decimal(destination_port))
    display_packet_field("Sequence Number", sequence_number, convert_hex_to_decimal(sequence_number))
    display_packet_field("Acknowledgement Number", acknowledgement_number, convert_hex_to_decimal(acknowledgement_number))
    display_packet_field("Data Offset", data_offset, convert_hex_to_decimal(data_offset))
    display_packet_field_for_flags("Reserved + Flags", reserved_and_flags, convert_hex_to_decimal(reserved_and_flags), reserved_and_flag_readable)
    display_packet_field_for_flags("- Reserved", reserved_and_flags[0], convert_hex_to_decimal(reserved_and_flags[0]), reserved_readable)
    display_packet_field("- CWR", cwr, convert_hex_to_decimal(cwr))
    display_packet_field("- ECE", ece, convert_hex_to_decimal(ece))
    display_packet_field("- URG", urg, convert_hex_to_decimal(urg))
    display_packet_field("- ACK", ack, convert_hex_to_decimal(ack))
    display_packet_field("- PSH", psh, convert_hex_to_decimal(psh))
    display_packet_field("- RES", res, convert_hex_to_decimal(res))
    display_packet_field("- SYN", syn, convert_hex_to_decimal(syn))
    display_packet_field("- FIN", fin, convert_hex_to_decimal(fin))
    display_packet_field("Window Size", window_size, convert_hex_to_decimal(window_size))
    display_packet_field("Checksum", checksum, convert_hex_to_decimal(checksum))
    display_packet_field("Urgent Pointer", urgent_pointer, convert_hex_to_decimal(urgent_pointer))
    display_packet_field("Options", options, "")
    display_packet_field("Data", data, convert_hex_to_text(data))

def parse_udp(hex_data):
    source_port, hex_data       = get_data_field(hex_data, 4) # 16 bits
    destination_port, hex_data  = get_data_field(hex_data, 4) # 16 bits
    length, hex_data            = get_data_field(hex_data, 4) # 16 bits
    checksum, hex_data          = get_data_field(hex_data, 4) # 16 bits

    display_packet_field("Source Port", source_port, convert_hex_to_decimal(source_port))
    display_packet_field("Destination Port", destination_port, convert_hex_to_decimal(destination_port))
    display_packet_field("Length", length, convert_hex_to_decimal(length))
    display_packet_field("Checksum", checksum, convert_hex_to_decimal(checksum))
