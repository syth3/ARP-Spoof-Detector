# ARP-Spoof-Detector
This Python program detects ARP spoofing by checking MAC addressing mapping to multiple IP addresses in the ARP table.

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
