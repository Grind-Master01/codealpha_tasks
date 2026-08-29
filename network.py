"""Network Packet Sniffer Module.

Captures nework traffic using Scapy for analyysis.
"""

from datetime import datetime                                          # It allows us to convert and format the time when a packet was captured.
from scapy.all import sniff                                            # sniff() is responsible for capturing network packets.
from scapy.layers.inet import IP, TCP, UDP, ICMP                       # These are used to check what type of network protocol a packet contains.
from scapy.packet import Raw                                           # Raw represents raw data/payload carried inside a packet.

packet_number = 0                                                      # Creates a variable to keep track of the number of packets captured.
total_payload_bytes =0                                                 # Creates a variable to store the total number of payload bytes. # It starts at 0.

def analyze_packet(packet):                                            # This function will be called whenever Scapy captures a packet.
    global packet_number                                               # Tells Python that we want to use the global packet_number variable.

    packet_number += 1                                                 # Increases the packet counter by 1 every time a packet is captured.

    if packet.haslayer(IP):                                            # Checks whether the captured packet contains an IP layer.

        timestamp = datetime.fromtimestamp(float(packet.time))         #Gets the packet's capture timestamp and converts it into a Python datetime object.
        time_string = timestamp.strftime("%H:%M:%S.%f")[:-3]           #Converts the timestamp into a readable format: Hours:Minutes:Seconds.Milliseconds

        print("\n===============================")
        print(f"PACKET #{packet_number}")
        print("=================================")

        print("Time                  :", time_string)                  # Displays the time the packet was captured.
        print("Source IP             :", packet[IP].src)               # Gets and displays the source IP address.  .src gets the source IP address from that layer.
        print("Destination IP        :", packet[IP].dst)               # Gets and displays the destination IP address.  .dst gets the destination IP address from the IP layer.

    if packet.haslayer(TCP):                                           # Checks whether the packet contains a TCP layer. 
        print("Protocol              : TCP")                           #Displays TCP as the protocol.
        print("Source Port           :", packet[TCP].sport)            # Gets and displays the TCP source port.
        print("Destination Port      :", packet[TCP].dport)            # Gets and displays the TCP destination port.

    elif packet.haslayer(UDP):
        print("Protocol              : UDP")
        print("Source Port           :", packet[UDP].sport)            #Same as TCP, but it will be for  UDP protocol.
        print("Destination Port      :", packet[UDP].dport)   

    elif packet.haslayer(ICMP):                                        #elif means if TCP and UDP packet is not available, check whether it contains ICMP.
        print("Protocol              : ICMP")
    else:                                                              # If the packet is not TCP, UDP, or ICMP, classify it as another/unknown protocol.
        print("Protocol              : Other")    
        
    if packet.haslayer(Raw):                                           # Raw represents the actual data/payload carried by the packet.  len() calculates how many bytes of data it contains.
        print("Payload Size          :", len(packet[Raw].load), "bytes")     


print("Network Sniffer Started..")
print("Press CTRL+C to stop.\n")

try:

  sniff(prn=analyze_packet)                                            # "Every time you capture a packet, send that packet to the analyze_packet() function."
except KeyboardInterrupt:

 print("\n\nStopping network sniffer..")

 print("Capture finished.")
 print("Total packets capured:", packet_number)






#Protocol	Meaning

#IP	       Internet Protocol
#TCP	       Transmission Control Protocol
#ICMP	   Internet Control Message Protocol