# Simple Cisco

A simple Cisco Aironet configuration script

ap.py is a telnet based python script for configuring based functions on Cisco
Aironet access points.

The script can:
- Locate the IP address of connected Cisco devices
- Configure the admin and enable passwords
- Configure a static or dynamic management IP
- Configure SSIDs with WPA2 security on both 2.4 and 5 GHz including separate SSIDs
- Disable and enable the access point's status LED
- Perform a factory reset, including maintaining or removing the IP configuration

## Usage:
```bash
ap.py [-p <pass> | --admin=<pass>] [-i <ip> | --ip=<ip>] [-c <path> | --config=<path>] [-S | --scan]
      [-m <mac-address> | --mac=<mac-address>] [-a | --all] [-l <on|off> | --led=<on|off>]
      [-I <ip:pass> | --init=<ip:pass>] [-r | --reset] [-w <on|off|clear> | --wifi=<on|off|clear>]
      [-5] [-2] [-s <ssid> | --ssid=<ssid>] [-k <psk> | --pass=<psk>]
```

## Installation
The script makes use of the [scapy](https://github.com/secdev/scapy)
library in order to perform CDP packet monitoring for the scan function.

```bash
pip install -r requirements.txt
```