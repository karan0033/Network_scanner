#!usr/bin/env python3
import scapy.all as scapy
import optparse

def input():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="[+] Target IP / IP Range")
    (option,arguments)=parser.parse_args()
    if not option.target:
        parser.error("[-] Use '--help' or '-h' for help ")
    return option

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_packet = arp_req/broadcast
    answered_list = scapy.srp(full_packet,timeout=1,verbose= False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"mac":element[1].psrc,"IP":element[1].hwsrc}
        client_list.append(client_dict)
    return  client_list

def print_scan(scan_list):
    print("IP\t\t\tMAC\n_________________________________________")
    for clients in scan_list:
        print(clients["IP"]+"\t\t"+ clients["mac"])

option = input()
scan_result = scan(option.target)                                                                                                                                    
print_scan(scan_result)
