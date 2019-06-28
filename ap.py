#! /usr/bin/env python3
import getopt
import sys
import json

from scan import cdp_scan
from cisco_telnet import Cisco


def load_config(path):
    with open(path) as f:
        config = json.load(f)
    ip = config.get('ip','')
    password = config.get('password','')
    return ip, password


def process_subcommand(argv):
    """ap.py is a telnet based python script for configuring based functions on Cisco
Aironet access points

Usage: ap.py <command> --admin=<new-password> --ip=<new-ip> [<options>] [<args>]
  or   ap.py <command> --config=<path> [<options>] [<args>]

Commands:
   scan   Monitor CDP packets for the IP address of connected Cisco devices
   init   Initialise an access point with a password and IP address
   wifi   Manipulate wi-fi functionality including setting the SSID
   led    Toggle the status LED on the access point
   reset  Factory reset the access point, including the IP address
    """
    __info__ = """Options:
{0} scan [-a|--all]
                CDP traffic is monitored for MAC and IP addresses, by default
                the scan terminates after a single device is discovered
 -a, --all      CDP traffic in monitored for MAC/IP addresses for 60 seconds
                regardless of how many devices are discovered

{0} init --admin=<new-password> --ip=<new-ip> --curr-ip=<ip> [--pass=<password>]
{0} init --admin=<new-password> --ip=<new-ip> --mac=<mac-address> [--pass=<password>]
{0} init --config=<path> --curr-ip=<ip> [--pass=<password>]
{0} init --config=<path> --mac=<mac-address> [--pass=<password>]
                The access point is configured with an admin and enable password,
                encryption is enabled and all the radios are configured for
                maximum range.
 -a, --admin    The password to be set for the user and enable passwords
 -i, --ip       The IP address to be set on the management interface
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively
     --curr-ip  The IP address which will be used to initially connect to the
                access point
 -m, --mac      The MAC address of the access point to be connected to. A 60
                second CDP scan is started to identify the IP of the device.
                On a factory reset device this will usually be the IPv6
                link-local address unless a DHCP server in present.
 -p, --pass     The password to be initially used for the user and enable credentials

{0} wifi --admin=<password> --ip=<ip> <on | off>
{0} wifi --config=<path> <on | off>
                Toggle the state the wireless radios of the access point
 -a, --admin    The password to be used for the user and enable credentials
 -i, --ip       The IP address which will be used to connect to the access point
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively

{0} wifi --admin=<password> --ip=<ip> clear
{0} wifi --config=<path> clear
                Remove all configured SSIDs from the access point
 -a, --admin    The password to be used for the user and enable credentials
 -i, --ip       The IP address which will be used to connect to the access point
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively

{0} wifi --admin=<password> --ip=<ip> [-5 | -2] --ssid=<ssid> --pass=<wpa_psk>
             [[-5 | -2] --ssid= ...]
{0} wifi --config=<path> [-5 | -2] --ssid=<ssid> --pass=<wpa_psk>
             [[-5 | -2] --ssid= ...]
                Configure the SSID to be used, the SSID can be limited to the
                5 GHz or 2.4 GHz radio or separate SSIDs can be given to the
                2.4 and 5 GHz radios.
                i.e. {0} wifi --config=ap.conf -5 --ssid='5GHzSSID' --pass="5GHzpass"
                            -2 --ssid='2.4GHzSSID' --pass="2.4GHzpass"
 -a, --admin    The password to be used for the user and enable credentials
 -i, --ip       The IP address which will be used to connect to the access point
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively
 -5             Only configure the following SSID on the 5 GHz radio
 -2             Only configure the following SSID on the 2.4 GHz radio
 -s, --ssid     The SSID to be used
 -p, --pass     The pre-shared key to be associated with the SSID

{0} led --admin=<password> --ip=<ip> <on | off>
{0} led --config=<path> <on | off>
                Toggle the state of the LED on the access point
 -a, --admin    The password to be used for the user and enable credentials
 -i, --ip       The IP address which will be used to connect to the access point
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively

{0} reset --admin=<password> --ip=<ip> [--all]
{0} reset --config=<path> [--all]
                Perform a factory reset on the access point, by default the IP
                address is maintained
 -a, --admin    The password to be used for the user and enable credentials
 -i, --ip       The IP address which will be used to connect to the access point
 -c, --config   The path of a config file containing json data for password
                and ip, which will be used in place of --admin and --ip respectively
     --all      Additionally clear the configured IP address

    """.format('ap.py')
    if len(argv) == 1:
        print(process_subcommand.__doc__)
        return 1
    if argv[1] == 'scan':
        scan_usage = """Usage: {0} scan [-a|--all]""".format(argv[0])
        try:
            opts, args = getopt.getopt(argv[2:], 'a', ['all'])
        except getopt.GetoptError:
            print(scan_usage)
            return 1
        opt = [x[0] for x in opts]
        if '-a' in opt or '--all'in opt:
            print('60 second scan started for all cisco devices')
            cdp = cdp_scan(all=True)
            for mac,ip in cdp.items():
                print(mac + " @ " + ip)
        else:  
            print('Started scanning for the access point')
            cdp = cdp_scan()
            for mac,ip in cdp.items():
                print(mac + " @ " + ip)
        return 0
    elif argv[1] == 'init':
        init_usage = """Usage:
        {0} init --admin=<new-password> --ip=<new-ip> --curr-ip=<ip> [--pass=<password>]
        {0} init --admin=<new-password> --ip=<new-ip> --mac=<mac-address> [--pass=<password>]
        {0} init --config=<path> --curr-ip=<ip> [--pass=<password>]
        {0} init --config=<path> --mac=<mac-address> [--pass=<password>]""".format(argv[0])
        try:
            opts, args = getopt.getopt(argv[2:], 'a:i:c:m:p:', ['admin=', 'ip=', 'config=', 'curr-ip=', 'mac=', 'pass='])
        except getopt.GetoptError:
            print(init_usage)
            return 1
        curr_ip = ''
        new_ip = ''
        curr_pass = 'Cisco'
        new_pass = ''

        for opt,arg in opts:
            if opt in ('-a','--admin'):
                new_pass = arg
            elif opt in ('-i','--ip'):
                new_ip = arg
            elif opt in ('-c','--config'):
                new_ip, new_pass = load_config(arg)
            elif opt == '--curr-ip':
                curr_ip = arg
            elif opt in ('-m','--mac'):
                print('Starting MAC address scan')
                cdp = cdp_scan(mac=arg)
                if arg not in cdp.keys():
                    print('MAC address {} was not found'.format(arg))
                    return 2
                
                if cdp[arg] == 'no IP':
                    print('MAC address {} has no IP'.format(arg))
                    return 2
                curr_ip = cdp[arg]
                print('MAC address found at {} '.format(curr_ip))
            elif opt in ('-p','--pass'):
                curr_pass = arg

        if '' in [curr_ip, new_ip, curr_pass, new_pass]:
            print(init_usage)
            return 1

        conn = Cisco(host=curr_ip ,password=curr_pass)
        conn.initialise(new_password=new_pass, new_addr=new_ip)
        return 0
    elif argv[1] == 'wifi':
        wifi_usage = """Usage:
        {0} wifi --admin=<password> --ip=<ip> <on | off | clear>
        {0} wifi --config=<path> <on | off | clear>
        {0} wifi --admin=<password> --ip=<ip> [-5 | -2] --ssid=<ssid> --pass=<wpa_psk> [<-5 | -2> --ssid=...]
        {0} wifi --config=<path> [-5 | -2] --ssid=<ssid> --pass=<wpa_psk> [<-5 | -2> --ssid=...]""".format(argv[0])
        try:
            opts, args = getopt.getopt(argv[2:], '52a:i:c:s:p:', ['admin=', 'ip=', 'config=', 'ssid=', 'pass='])
        except getopt.GetoptError:
            print(wifi_usage)
            return 1
        curr_ip = ''
        curr_pass = ''
        ssid5 = None
        ssid2 = None
        psk5 = None
        psk2 = None
        ssid_toggle = (True, True)
        ssid_entry = False

        for opt,arg in opts:
            if opt in ('-a','--admin'):
                curr_pass = arg
            elif opt in ('-i','--ip'):
                curr_ip = arg
            elif opt in ('-c','--config'):
                curr_ip, curr_pass = load_config(arg)
            elif opt in ('-s','--ssid'):
                ssid_entry = True
                if ssid_toggle[0]: # Configure 5GHz radio
                    ssid5 = arg
                if ssid_toggle[1]: # Configure 5GHz radio
                    ssid2 = arg
            elif opt in ('-p','--pass'):
                if ssid_toggle[0]: # Configure 5GHz radio
                    psk5 = arg
                if ssid_toggle[1]: # Configure 5GHz radio
                    psk2 = arg
            elif opt == '-5':
                ssid_toggle = (True,False)
            elif opt == '-2':
                ssid_toggle = (False,True)

        if '' in [curr_ip, curr_pass]:
            print(wifi_usage)
            return 1
        conn = Cisco(host=curr_ip ,password=curr_pass)
        if ssid_entry: # type 3 arguments
            # skip blank ssids, ssid len <32, psk len 8-63
            if ssid2 and (len(ssid2) not in range(32) or len(psk2) not in range(8,64)):
                print('SSIDs must be below 32 characters and passphrases must be between 8 and 63 characters')
                return 2
            if ssid5 and (len(ssid5) not in range(32) or len(psk5) not in range(8,64)):
                print('SSIDs must be below 32 characters and passphrases must be between 8 and 63 characters')
                return 2
            conn.wifi_ssid(ssid_2=ssid2, psk_2=psk2,ssid_5=ssid5,psk_5=psk5)
        elif len(args) != 1:
            print(wifi_usage)
            return 1
        elif args[0] == 'on':
            conn.wifi_enable()
        elif args[0] == 'off':
            conn.wifi_disable()
        elif args[0] == 'clear':
            conn.wifi_clear()
        else:
            print(wifi_usage)
            return 1
        return 0
    elif argv[1] == 'led':
        led_usage = '''Usage: 
        {0} led --admin=<password> --ip=<ip> <on|off>
        {0} led --config=<confg-path> <on|off>'''.format(argv[0])
        try:
            opts, args = getopt.getopt(argv[2:], 'a:i:c:', ['admin=', 'ip=', 'config='])
        except getopt.GetoptError:
            print(led_usage)
            return 1
        curr_ip = ''
        curr_pass = ''

        for opt,arg in opts:
            if opt in ('-a','--admin'):
                curr_pass = arg
            elif opt in ('-i','--ip'):
                curr_ip = arg
            elif opt in ('-c','--config'):
                curr_ip, curr_pass = load_config(arg)
        
        if '' in [curr_ip, curr_pass]:
            print(led_usage)
            return 1

        conn = Cisco(host=curr_ip ,password=curr_pass)
        if len(args) and args[0] == 'on':
            conn.led_enable()
        elif len(args) and args[0] == 'off':
            conn.led_disable()
        else:
            print(led_usage)
            return 1
        return 0
    elif argv[1] == 'reset':
        reset_usage = '''Usage:
        {0} reset --admin=<password> --ip=<ip> [--all]
        {0} reset --config=<path> [--all]'''.format(argv[0])
        try:
            opts, args = getopt.getopt(argv[2:], 'a:i:c:', ['admin=', 'ip=', 'config=', 'all'])
        except getopt.GetoptError:
            print(reset_usage)
            return 1
        curr_ip = ''
        curr_pass = ''
        clear_ip = False

        for opt,arg in opts:
            if opt in ('-a','--admin'):
                curr_pass = arg
            elif opt in ('-i','--ip'):
                curr_ip = arg
            elif opt in ('-c','--config'):
                curr_ip, curr_pass = load_config(arg)
            elif opt == '--all':
                clear_ip = True

        if '' in [curr_ip, curr_pass]:
            print(reset_usage)
            return 1
        
        conn = Cisco(host=curr_ip ,password=curr_pass)
        if clear_ip:
            conn.reset(keep_ip=False)
        else:
            conn.reset()
    elif argv[1] == 'help':
        print(process_subcommand.__doc__)
        print(__info__)

    print(process_subcommand.__doc__)
    return 0

if __name__ == "__main__":
    exit(process_subcommand(sys.argv))