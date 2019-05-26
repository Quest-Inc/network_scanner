#!/usr/bin/env python

# scapy doesnt come pre installed in python3
# pip install scapy-python3 (for python 2.7)
# pip3 install scapy-python3 (for python 3)
import scapy.all as scapy
import optparse


# successor for optparse as is deprecated though works
# import argparse

# now get arguments for scanner // use parser
def get_ip():
    parser = optparse.OptionParser()
    # parser = argparse.ArgumentParser()
    parser.add_option("-r", "--range", dest="ipaddr",
                      help="Specify an IP Address or an IP Range")
    # parser.add_argument("-t", "--target", dest="target",
    #                       help="Target IP / IP Range")
    (options, args) = parser.parse_args()
    # in this case it returns the options so no arguments

    if not options.ipaddr:
        # code to handle err if no ip range
        parser.error("[-] Specify an IP Address or a range of IP Address"
                     " --help for more details")
    return options


# packet delivered to all hosts
def scan(ip):
    # use ARP to ask who has target ip
    arp_request = scapy.ARP(pdst=ip)

    # ethernet frame and append arp_request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # combine both packets in one
    arp_request_broadcast = broadcast / arp_request

    # srp send packet with a custom ether part
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]

    clients_list = []
    # for loop to iterate elements in the answered list
    for element in answered_list:
        #  now a dictionary
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    #  Header
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


# Name of variables you want to learn
# scapy.ls(scapy.ARP()) # show fields we can set


ip = get_ip()
# get the ip address or whole ip range to ip variable

scan_result = scan(ip.ipaddr)
# use the ipaddr instance argument to use as a input_ip to scan function

print_result(scan_result)
# represent the scan result in easier way
