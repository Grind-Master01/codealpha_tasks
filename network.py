"""Network Packet Sniffer Module.

Captures nework traffic using Scapy for analyysis.
"""

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

print("Network Sniffer Started..")

packets =sniff(count=5)

for packet in packets:
    
    if packet.haslayer(IP):
        print("\n========")
        print("PACKETS")
        print("==========")
        print("Source IP             :", packet[IP].src)
        print("Destination IP        :", packet[IP].dst)

    if packet.haslayer(TCP):
        print("Protocol              : TCP")
        print("Source Port           :", packet[TCP].sport)
        print("Destination Port      :", packet[TCP].dport)

    elif packet.haslayer(UDP):
        print("Protocol              : UDP")
        print("Source Port           :", packet[UDP].sport)
        print("Destination Port      :", packet[UDP].dport)   

    elif packet.haslayer(ICMP):
        print("Protocol              : ICMP")
    else:
        print("Protocol              : Other")    
        
    if packet.haslayer(Raw):
        print("Payload Size          :", len(packet[Raw].load), "bytes")


print("\nCapture finished.")










#packets = packets[0]
#packets.show()

#print(packets)
#print("Capture finished.")
