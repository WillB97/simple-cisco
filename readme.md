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
- Configure the DHCP server on the AP
- Perform a factory reset, including maintaining or removing the IP configuration

## Usage:
```bash
ap.py [-p <pass> | --admin=<pass>] [-i <ip> | --ip=<ip>] [-c <path> | --config=<path>] [-S | --scan]
      [-m <mac-address> | --mac=<mac-address>] [-a | --all] [-l <on|off> | --led=<on|off>]
      [-I <ip:pass> | --init=<ip:pass>] [-r | --reset] [-d <start>-<end>|off | --dhcp <start>-<end>|off]
      [-w <on|off|clear> | --wifi=<on|off|clear>] [-5] [-2] [-s <ssid> | --ssid=<ssid>] [-k <psk> | --pass=<psk>]
```

__Note:__ The script does not (currently) support setting an IPv6 address or the MAC based options returning a unique IPv6 address.
However when an IPv4 address in the appropriate subnet is not available IPv6 link-local addresses
are used to connect so the IPv6 stack should be enabled for proper functionality.

## Installation
The script makes use of the [scapy](https://github.com/secdev/scapy)
library in order to perform CDP packet monitoring for the scan function.

```bash
pip install -r requirements.txt
```