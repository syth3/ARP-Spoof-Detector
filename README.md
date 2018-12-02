# ARP-Spoof-Detector
This Python program detects ARP spoofing by checking for MAC addresses that map to multiple IP addresses in the ARP table.
This script is only meant to be run on Windows.

## Installation
```
pip3 install -r requirements.txt
```

## Running the script in the foreground
```
python detector.pyw adapter_description [sleep_time_seconds]
```

## Running the script in the background
```
pythonw detector.pyw adapter_description [sleep_time_seconds]
```
