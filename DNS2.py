from __future__ import print_function
import sys
from scapy.all import *
 
## Create a Packet Counter
counter = 0
 
## Define our Custom Action function
if len(sys.argv) < 2:
	print("Command Example: DNS2.py <ip of target host>")
	sys.exit()
ip = sys.argv[1]
def custom_action(packet):
    global counter
    counter += 1
    if packet.haslayer(DNS):
     ip_src=packet[IP].src
     ip_dst=packet[IP].dst
     website=packet.getlayer(DNS).qd.qname
     if website[0] == "w" and website[1] == "w":
      if website[3] != "-":
       if ip_src == ip:
        print("Source: "+str(ip_src)+ " Destination: "+ str(ip_dst)+" Website: "+str(website))
## Setup sniff, filtering for IP traffic
print("Sniffing started")
sniff(filter="ip", prn=custom_action)
