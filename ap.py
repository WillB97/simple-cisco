#! /usr/bin/env python3
import getopt
import sys
import json
from inspect import cleandoc as trim

from scan import cdp_scan
from cisco_telnet import Cisco


def load_config(path):
    with open(path) as f:
        config = json.load(f)
    ip = config.get('ip','')
    password = config.get('password','')
    return ip, password

def process_arguments(argv):
    """
        ap.py is a telnet based python script for configuring based functions on Cisco Aironet access points

        Usage: ap.py <option>...

        Options
         -p, --admin=<pass>         The password to be used for the user and enable credentials.
         -i, --ip=<ip>              The IP address which will be used to connect to the access point.
         -c, --config=<path>        The path of a config file containing json data for password
                                    and ip, which will be used in place of --admin and --ip respectively.
         -S, --scan                 Monitor CDP traffic for IP address(es) of connected Cisco devices,
                                    by default the scan terminates after a single device is discovered.
                                    When used in combination with --all the scan runs for 
                                    a fixed duration of 60 seconds.
         -m, --mac=<mac-address>    The MAC address of the access point to be connected to.
                                    A CDP scan will be started to identify the IP of the device.
                                    On a factory reset device this will usually be the IPv6
                                    link-local address unless a DHCP server in present.
         -A, --arp                  Use arp requests for the local subnets when looking up MAC addresses.
                                    This is faster than a CDP scan when the AP is in a local subnet.
                                    A CDP scan is run if ARP does not find the MAC address.
         -a, --all                  When used in combination with --scan the scan will run for
                                    60 seconds regardless of devices found. 
         -l, --led=<on|off>         Sets the state of the status LED on the access point.
         -I, --init=<ip:pass>       Configure the access point with an admin and enable password,
                                    enable encryption and configure all radios for maximum range.
                                    The argument contains the IP address and password to be set,
                                    separated by a colon.
         -r, --reset                Perform a factory reset on the access point. When used in
                                    combination with --all the IP configuration is also cleared.
         -w, --wifi=<on|off|clear>  Toggle the state the wireless radios of the access point, or
                                    clear all configured SSIDs from the access point
         -d, --dhcp=<start>-<end>|off
                                    Toggle the state of the internal DHCP server. The server is enabled
                                    by providing the lower octet of the top and bottom IP addresses.
                                    The rest of the address will be extracted from the AP management address.
         -5                         Only configure the following SSID on the 5 GHz radio.
         -2                         Only configure the following SSID on the 2.4 GHz radio.
         -s, --ssid=<ssid>          The SSID to be configured on the access point,
                                    this is limited to 63 characters.
         -k, --pass=<psk>           The pre-shared WPA2 key to be associated with the SSID,
                                    this must between 8 and 32 characters.
        Examples
         ap.py --admin=Cisco --scan --all --init=192.168.1.5:Password
         ap.py --config=ap.conf -5 --ssid='5GHzSSID' --pass="5GHzpass" -2 --ssid='2.4GHzSSID' --pass="2.4GHzpass"
         ap.py --admin=Cisco --mac=00:07:7d:00:00:01 --led=off --wifi=clear
         ap.py --admin=Cisco --ip=192.168.0.2 --reset

    """

    __usage__ = """
        Usage: {0} [-p <pass> | --admin=<pass>] [-i <ip> | --ip=<ip>] [-c <path> | --config=<path>] [-S | --scan]
                     [-m <mac-address> | --mac=<mac-address>] [-A | --arp] [-a | --all] [-l <on|off> | --led=<on|off>]
                     [-I <ip:pass> | --init=<ip:pass>] [-r | --reset] [-d <start>-<end>|off | --dhcp <start>-<end>|off]
                     [-w <on|off|clear> | --wifi=<on|off|clear>] [-5] [-2] [-s <ssid> | --ssid=<ssid>] [-k <psk> | --pass=<psk>]
    """.format(sys.argv[0])

    curr_pass = ''
    curr_addr = ''
    new_pass = ''
    new_addr = ''
    mac_addr = None
    ssid5 = None
    ssid2 = None
    psk5 = None
    psk2 = None
    ssid_toggle = (True, True)
    dhcp_vals = []
    all_state = False
    init_state = False
    scan_state = False
    wifi_clear = False
    dhcp_state = None
    ssid_entry = False
    wifi_state = None
    led_state = None
    reset_state = False
    debug_state = False
    arp_state = False

    if len(argv) == 1:
        print(trim(process_arguments.__doc__))
        return 1
    try:
        opts, args = getopt.getopt(argv[1:], 'p:i:c:Sm:al:I:rw:52s:k:hd:vA', ['admin=', 'ip=', 'config=',
            'scan','mac', 'all', 'led=', 'init=', 'reset', 'wifi=', 'ssid=', 'pass=', 'help', 'dhcp=', 'arp'])
    except getopt.GetoptError:
        print(trim(__usage__))
        return 2

    for opt,arg in opts:
        if opt in ('-p','--admin'):
            curr_pass = arg
        elif opt in ('-i','--ip'):
            curr_addr = arg
        elif opt in ('-c','--config'):
            curr_addr, curr_pass = load_config(arg)
        elif opt in ('-S','--scan'):
            scan_state = True
        elif opt in ('-m','--mac'):
            mac_addr = arg
        elif opt in ('-a','--all'):
            all_state = True
        elif opt in ('-l','--led'):
            if arg.lower() in ('on','+'):
                led_state = True
            elif arg.lower() in ('off','-'):
                led_state = False
        elif opt in ('-I','--init'): #--init=<ip:pass>
            arg_parts = arg.split(':',1)
            if len(arg_parts) == 2:
                init_state = True
                new_addr = arg_parts[0]
                new_pass = arg_parts[1]
            else:
                print(' --init argument is in the form <ip>:<pass>')
        elif opt in ('-r','--reset'):
            reset_state = True
        elif opt in ('-w','--wifi'):
            if arg.lower() in ('on','+'):
                wifi_state = True
            elif arg.lower() in ('off','-'):
                wifi_state = False
            elif arg.lower() in ('clear','x'):
                wifi_clear = True
        elif opt in ('-5',):
            ssid_toggle = (True,False)
        elif opt in ('-2',):
            ssid_toggle = (False,True)
        elif opt in ('-s','--ssid'):
            ssid_entry = True
            if ssid_toggle[0]: # Configure 5GHz radio
                ssid5 = arg
            if ssid_toggle[1]: # Configure 5GHz radio
                ssid2 = arg
        elif opt in ('-k','--pass'):
            if ssid_toggle[0]: # Configure 5GHz radio
                psk5 = arg
            if ssid_toggle[1]: # Configure 5GHz radio
                psk2 = arg
        elif opt in ('-h','--help'):
            print(trim(__usage__))
            return 0
        elif opt in ('-d','--dhcp'):
            arg_parts = arg.split('-',1)
            if arg.lower() in ('off','-'):
                dhcp_state = False
            elif len(arg_parts) == 2:
                if not arg_parts[0].isdigit() or not arg_parts[1].isdigit():
                    print('--dhcp start and end values are the lower octet of the IP addresses')
                else:
                    dhcp_state = True
                    dhcp_vals = arg_parts
            else:
                print(' --dhcp argument is in the form <start>-<end> or off')
        elif opt in ('-v'):
            debug_state = True
        elif opt in ('-A','--arp'):
            arp_state = True

    if args:
        print(trim(__usage__))
        return 2

    telnet_state = True in (init_state, wifi_clear,ssid_entry,wifi_state,led_state,reset_state,dhcp_state)
    telnet_state |= False in (wifi_state,led_state,dhcp_state)

    if mac_addr: # mac scan
        print('Started scanning for MAC address ' + mac_addr)
        cdp = cdp_scan(mac=mac_addr,arp=arp_state)
        if cdp:
            ip  = list(cdp.values())[0]
            if ip[0]:
                curr_addr = ip[1]
                print('MAC address {} found at {}'.format(mac_addr,ip[1]))
            else:
                print('MAC address {} has no IP associated with it. Try connecting a DHCP server'.format(mac_addr))
        else:
            print('MAC address {} not found'.format(mac_addr))
    if scan_state: # scan (interactive)
        if all_state:
            print('60 second scan started for all cisco devices')
        else:
            print('Started scanning for the access point')
        cdp = cdp_scan(all=all_state)
        if telnet_state:
            i = 0
            for mac,ip in cdp.items(): # offer found devices to user
                print('{}: {} @ {}'.format(i,mac,', '.join(ip[0])))
                i += 1
            print('{}: skip'.format(i))
            x = input('Select device to be configured: ')
            if x.isdigit() and int(x) in range(i):
                curr_addr = list(cdp.values())[int(x)][1]
        else:
            for mac,ip in cdp.items():
                print('{} @ {}'.format(mac,', '.join(ip[0])))
    conn = None
    try:
        if telnet_state: # validate login creds
            if curr_pass == '' or curr_addr == '':
                print('Options --led, --init, --reset, --wifi, --ssid require --admin and --ip to be present')
                return 2
            conn = Cisco(host=curr_addr,password=curr_pass)
            if debug_state:
                conn.tn.set_debuglevel(1)
        if init_state: # init
            if new_pass == '':
                print('--init requires a non-blank password')
                return 1
            conn.initialise(new_password=new_pass,new_addr=new_addr,batch=True)
        if wifi_clear: # wifi clear
            conn.wifi_clear(batch=True)
        if dhcp_state != None: # dhcp
            if dhcp_state == False:
                conn.dhcp_off(batch=True)
            else:
                try:
                    conn.dhcp(dhcp_vals[0], dhcp_vals[1], batch=True)
                except ValueError as e:
                    print(e)
        if ssid_entry: # ssid entry
            # skip blank ssids, ssid len <32, psk len 8-63
            if ssid2 and (len(ssid2) not in range(32) or len(psk2) not in range(8,64)):
                print('SSIDs must be below 32 characters and passphrases must be between 8 and 63 characters')
                return 2
            if ssid5 and (len(ssid5) not in range(32) or len(psk5) not in range(8,64)):
                print('SSIDs must be below 32 characters and passphrases must be between 8 and 63 characters')
                return 2
            conn.wifi_ssid(ssid_2=ssid2, psk_2=psk2,ssid_5=ssid5,psk_5=psk5, batch=True)
        if wifi_state != None: # wifi state
            if wifi_state:
                conn.wifi_enable(batch=True)
            else:
                conn.wifi_disable(batch=True)
        if led_state != None: # led state
            if led_state:
                conn.led_enable(batch=True)
            else:
                conn.led_disable(batch=True)
        if reset_state: # reset
            if all_state:
                conn.reset(keep_ip=False, batch=True)
            else:
                conn.reset(batch=True)
            return 0

        if telnet_state:
            conn.run_command('exit')
    except ValueError as e:
        print(e)
        if conn:
            conn.run_command('exit')

if __name__ == "__main__":
    exit(process_arguments(sys.argv))
