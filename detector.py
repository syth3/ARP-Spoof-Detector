import ctypes
import sys
import subprocess

import wmi


def get_interface_ip(target_interface, all=False):
    c = wmi.WMI ()
    ipaddress = ""
    for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
        if interface.Description == target_interface:
            ipaddress = interface.IPAddress[0]
    return ipaddress


def get_range(arp_table, interface_ip):
    count = 0
    starting_line = 0
    ending_line = 0
    current_interface = ""
    for line in arp_table:
        # When you find the desired interface
        if "Interface: " + interface_ip in line:
            starting_line = count+1
            current_interface = "Interface: " + interface_ip
            # When you get to the next interface, aka the end of the desired one
        if "Interface" in line and "Interface: " + interface_ip not in line and current_interface == "Interface: " + interface_ip:
            ending_line = count-2
        count += 1
    if ending_line == 0:
        ending_line = count-2
    return starting_line, ending_line


def open_window(text, title):
    ctypes.windll.user32.MessageBoxW(0, text, title, 0)


def find_arp_poisining(arp_entry):
    attacker_ips = []
    attacker_macs = []
    mac_to_ip_dict = {}
    for line in arp_entry:
    for i in range(1, len(arp_entry)):
        line = arp_entry[i].strip()
        split_line = line.split()
        if split_line[2] == "dynamic":
            if split_line[1] in mac_to_ip_dict:
                mac_to_ip_dict[split_line[1]].append(split_line[0])
            else:
                mac_to_ip_dict[split_line[1]] = [split_line[0]]
    for key in mac_to_ip_dict:
        if len(mac_to_ip_dict[key]) > 1:
            open_window("The following IPs have the same MAC: " + ', '.join(mac_to_ip_dict[key]), "ARP Poisoning Detected")


def main():
    interface_description = sys.argv[1]
    interface_ip = get_interface_ip(interface_description)
    arp_table = (subprocess.check_output(("arp", "-a")).decode("utf-8")).split("\n")
    starting_line, ending_line = get_range(arp_table, interface_ip)
    find_arp_poisining(arp_table[starting_line: ending_line+1])

        
    
main()
