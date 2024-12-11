from scapy.all import sniff, Ether, IP
import struct

# Callback function to process captured packets
def packet_callback(packet):
    if packet.haslayer(Ether):
        # Extract Ethernet frame details
        dest_mac = packet[Ether].dst
        src_mac = packet[Ether].src
        eth_proto = packet[Ether].type
        print("\nEthernet Frame:")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {hex(eth_proto)}")

        # If it's an IP packet (eth_proto 0x0800 = IPv4)
        if eth_proto == 0x0800 and packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            print("IP Packet:")
            print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")

            # Custom handling based on protocol
            payload = bytes(packet[IP].payload)
            if proto == 1:  # ICMP
                icmp_type, code, checksum, rest = icmp_packet(payload)
                print(f"ICMP -> Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
            elif proto == 6:  # TCP
                tcp_data = tcp_segment(payload)
                print("TCP ->", tcp_data)
            elif proto == 17:  # UDP
                udp_data = udp_segment(payload)
                print("UDP ->", udp_data)

# Function to unpack an IPv4 packet manually
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Helper function to convert a raw IP address to a readable format
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    source_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # Extract the offset (header length in words)
    flags = offset_reserved_flags & 0x1FF  # Extract the last 9 bits for flags
    payload = data[offset:]

    try:
        decoded_payload = payload.decode(errors="ignore")
        lines = decoded_payload.splitlines()
    except UnicodeDecodeError:
        lines = ["[Non-Text Payload]"]

    return {
        "Source Port": source_port,
        "Destination Port": dest_port,
        "Sequence": sequence,
        "Acknowledgment": acknowledgement,
        "Header Length": offset,
        "Flags": {
            "URG": (flags & 32) >> 5,
            "ACK": (flags & 16) >> 4,
            "PSH": (flags & 8) >> 3,
            "RST": (flags & 4) >> 2,
            "SYN": (flags & 2) >> 1,
            "FIN": flags & 1
        },
        "payload": lines
    }

# Unpack UDP segment
def udp_segment(data):
    # UDP header structure: Source Port, Destination Port, Length, Checksum
    source_port, dest_port, length, checksum = struct.unpack('! H H H H', data[:8])

    # Remaining data is the payload
    payload = data[8:]

    return {
        "Source Port": source_port,
        "Destination Port": dest_port,
        "Length": length,
        "Checksum": checksum,
        "Payload": payload
    }

# Main function to start sniffing
def main():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)  # store=0 ensures packets are not stored in memory

if __name__ == "__main__":
    main()
