import csv
import os
from scapy.all import sniff, IP

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

log_file = "logs/packets.csv"

# Create CSV file if it doesn't exist
if not os.path.exists(log_file):
    with open(log_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Packet No",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Packet Size"
        ])


def get_protocol_name(protocol):
    if protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    elif protocol == 1:
        return "ICMP"
    else:
        return "Other"


def process_packet(packet):
    global packet_count, tcp_count, udp_count, icmp_count, other_count

    packet_count += 1

    print("\n" + "=" * 50)
    print(f"Packet Number : {packet_count}")

    if IP in packet:

        protocol = get_protocol_name(packet[IP].proto)

        if protocol == "TCP":
            tcp_count += 1
        elif protocol == "UDP":
            udp_count += 1
        elif protocol == "ICMP":
            icmp_count += 1
        else:
            other_count += 1

        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Size    : {len(packet)} Bytes")

        with open(log_file, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                packet_count,
                packet[IP].src,
                packet[IP].dst,
                protocol,
                len(packet)
            ])

    else:
        other_count += 1
        print("Non-IP Packet")


def show_statistics():
    print("\n" + "=" * 50)
    print("          Packet Statistics")
    print("=" * 50)
    print(f"Total Packets : {packet_count}")
    print(f"TCP Packets   : {tcp_count}")
    print(f"UDP Packets   : {udp_count}")
    print(f"ICMP Packets  : {icmp_count}")
    print(f"Other Packets : {other_count}")
    print("=" * 50)


def start_capture():
    print("Starting packet capture...\n")

    sniff(count=5, prn=process_packet)

    print("\nPacket capture completed.")
    print(f"Packet details saved to: {log_file}")

    show_statistics()


if __name__ == "__main__":
    start_capture()