#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # creating a  network frame
    arp_request_broadcast = broadcast/arp_request   # creating a new packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # send the packet and return the response

    print("IP\t\t\tMAC ADDRESS\n-----------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

scan("10.0.2.1/24")