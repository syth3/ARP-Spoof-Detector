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


def main():
    interface_description = sys.argv[1]
    print("IP of {} is {}".format(interface_description, get_interface_ip(interface_description)))

    
main()
