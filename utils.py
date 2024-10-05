import sys

def get_data_field(hex_data, hex_length):
    if len(hex_data) == 0:
        sys.exit("Packet is empty. Try again.")

    data_field = hex_data[:hex_length]
    hex_data = hex_data[hex_length:]

    return data_field, hex_data

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
