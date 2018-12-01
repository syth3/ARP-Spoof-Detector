'''
file: detector.pyw
language: python3
author: Jacob Brown jmb7438@rit.edu
description: Detect ARP Poisoning by looking for the same MAC address tied to different IP addressed
 in the arp table. This program is meant to be run on Windows.
'''

import ctypes
import sys
import subprocess
import time

import wmi


def get_interface_ip(target_interface):
    """
    Return IP address of the given the interface description. The interface description
    can be found by using the "ipconfig /all" command and looking for the "Description" row
    under the desired adapter.
    
    Parameters
    ----------
    target_interface : string
        interface_description to get the IP of
    
    Returns
    -------
    string
        IP address of the specified target_inteface
    """

    c = wmi.WMI ()
    ipaddress = ""
    for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
        if interface.Description == target_interface:
            ipaddress = interface.IPAddress[0]
    return ipaddress


def get_range(arp_table, interface_ip):
    """
    Given the output of "arp -a", find the arp entries that correspond to the specified IP address
    
    Parameters
    ----------
    arp_table : list
        "arp -a" output
    interface_ip : string
        IP to find the arp entries of
    
    Returns
    -------
    int, int
        return the starting index in the arp table, and ending index corresponding to the desired section
    """
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
    """
    Make a pop up window in Windows
    
    Parameters
    ----------
    text : string
        text to be displayed in the window
    title : string
        title to be displayed in the window
    Returns
    -------
    int
        status of button pressed on the popup window
    
    """
    instruction_string = "Abort -> kill program entirely\n" \
                     "Retry -> keep checking for ARP poisoning corresponding to the above MAC\n" \
                     "Ignore -> stop checking for ARP poisonig corresponsing to the above MAC"
    return ctypes.windll.user32.MessageBoxW(0, text + "\n\nWhich button do I press?\n" + instruction_string, title, 2)


def find_arp_poisining(arp_entry, ignore_these_macs):
    """
    Create a dictionary mapping MAC addresses to corresponding IP addresses.
    If a MAC address has more than one IP address associated with it, alert the user 
    with a popup window.
    
    Parameters
    ----------
    arp_entry : list
        list of arp entries each specifying a IP address, MAC address, and type
    ignore_these_macs : list
        list of MAC addresses to ignore possible ARP poisoning on
    Returns
    -------
    list of int, string tuples
        list of status number, mac address tuples
    
    """
    mac_to_ip_dict = {}
    poisoned_macs = []
    for i in range(1, len(arp_entry)):
        line = arp_entry[i].strip()
        split_line = line.split()
        if split_line[2] == "dynamic":
            if split_line[1] in mac_to_ip_dict:
                mac_to_ip_dict[split_line[1]].append(split_line[0])
            else:
                mac_to_ip_dict[split_line[1]] = [split_line[0]]
    for mac in mac_to_ip_dict:
        if len(mac_to_ip_dict[mac]) > 1 and mac not in ignore_these_macs:
            status = open_window("The following MAC has more than one IP addresses linked to it\n {} -> {}".format(mac, ', '.join(mac_to_ip_dict[mac])), "Possible ARP Poisoning Detected")
            poisoned_macs.append((status, mac))
    return poisoned_macs


def main():
    """
    1) Collect input and display help message if needed
    2) Get IP associated with interface given
    3) Check for arp poisoning in a continous loop 
    
    """

    if len(sys.argv) != 2:
        print("Usage: detector.pyw \"<adapter_description>\"")
        print("For more help: dector.pyw -h or detector.pyw --help")
        exit(1)
    if "-h" in sys.argv or "--help" in sys.argv:
        print("This program detects ARP poisoning by checking for duplicate MAC addresses in the ARP table for dynamic entries.")
        print("For the first argument to this script, run ipconfig /all, find your adapter of choice, and copy and paste the description for that adapter")
        exit(0)
    interface_description = sys.argv[1]
    interface_ip = get_interface_ip(interface_description)
    if len(interface_ip) < 7:
        print("Could not find an IP address for the following interface: {}".format(interface_description))
        exit(1)
    CREATE_NO_WINDOW = 0x08000000
    ignore_these_macs = []
    while(True):
        arp_table = (subprocess.check_output(("arp", "-a"), creationflags=CREATE_NO_WINDOW).decode("utf-8")).split("\n")
        starting_line, ending_line = get_range(arp_table, interface_ip)
        statuses = find_arp_poisining(arp_table[starting_line: ending_line+1], ignore_these_macs)
        for status in statuses:
            # Abort
            if status[0] == 3:
                exit(0)
            # Retry
            if status[0] == 4:
                pass
            # Ignore
            if status[0] == 5:
                ignore_these_macs.append(status[1])
        time.sleep(5)

        
    
main()
