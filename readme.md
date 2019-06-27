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
ap.py <command> --admin=<new-password> --ip=<new-ip> [<options>] [<args>]
ap.py <command> --config=<path> [<options>] [<args>]
```

Commands:

    scan   Monitor CDP packets for the IP address of connected Cisco devices
    init   Initialise an access point with a password and IP address
    wifi   Manipulate wi-fi functionality including setting the SSID
    led    Toggle the status LED on the access point
    reset  Factory reset the access point, including the IP address


## Installation
The script makes use of the [scapy](https://github.com/secdev/scapy) library in order to perform CDP packet monitoring.

```bash
pip install -r requirements.txt
```