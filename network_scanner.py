#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/ IP range")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # creating a  network frame
    arp_request_broadcast = broadcast/arp_request   # creating a new packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # send the packet and return the response

    clients_list = []  # creating a client list
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  # creating a dictionary to store IP and MAC address from client list
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC ADDRESS\n-----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

# main function
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)