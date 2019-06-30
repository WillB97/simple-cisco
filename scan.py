#! /usr/bin/env python3
import re
from ipaddress import ip_network

spec_nets = ('169.254.','224.','225.','226.','227.','228.','229.',
            '230.','231.','232.','233.','234.','235.','236.',
            '237.','238.','239.','255.','127.','0.0.0.0')

def cdp_scan(all=False, mac=None, arp=False):
    try:
        from scapy.all import get_if_list, get_if_addr, load_contrib, sniff, IP, conf, arping
    except ImportError:
        print('Scan functionality requires the scapy library to be installed')
        print('Use: "pip install scapy"')
        exit(-1)

    load_contrib("cdp")
    addr_list=[]
    cisco = {}

    for addr in get_if_list():
        ## adapt to limit interfaces to eth/wifi only
        if get_if_addr(addr) not in ['0.0.0.0', '127.0.0.1']: # ignore interfaces without ip addresses and localhost
            addr_list.append(addr)

    if mac:
        if arp:
            data = str(conf.route).splitlines()[1:]
            conf.verb = 0
            for x in data:
                x_arr = x.split()
                if not x_arr[0].startswith(spec_nets) and not x_arr[1].endswith('.255'): # remove multicast addresses
                    ip_net = ip_network(x_arr[0] + '/' + x_arr[1]).exploded
                    print('arp scanning ' + ip_net)
                    scan = arping(ip_net)[0]
                    for pack in scan:
                        if pack[1].hwsrc == mac:
                            return {pack[1].hwsrc: ([pack[1].psrc], pack[1].psrc)}
        p1 = sniff(iface=addr_list, timeout=360, filter="ether dst 01:00:0c:cc:cc:cc", stop_filter=lambda x: x.src == mac)
        if len(p1) and p1[-1].src == mac:
            p = [p1[-1]]
        else:
            p = []
    else:
        if all:
            p = sniff(iface=addr_list, timeout=60, filter="ether dst 01:00:0c:cc:cc:cc")
        else:
            p = sniff(iface=addr_list, timeout=60, count=1, filter="ether dst 01:00:0c:cc:cc:cc")

    for packet in p:
        pkg_addr = []
        pref_ip = ''
        for i in range(packet['CDPMsgAddr'].naddr):
            if packet['CDPMsgAddr'].addr[i].addr.startswith('fe80:'):
                pkg_addr.append(packet['CDPMsgAddr'].addr[i].addr + '%' + packet.sniffed_on)
            else:
                pkg_addr.append(packet['CDPMsgAddr'].addr[i].addr)
        if packet['CDPMsgAddr'].naddr:
            for ip in pkg_addr:
                if ip.startswith('fe80:'): # use link-local IPv6 if reached
                    pref_ip = ip
                    break
                if not re.search(r'^([0-2]?[0-9]{1,2}\.){3}[0-2]?[0-9]{1,2}$',ip): # skip other IPv6 addresses
                    continue
                if IP(dst=ip).route()[1] != '0.0.0.0' and IP(dst=ip).route()[2] == '0.0.0.0': # IPv4 address is routable
                    pref_ip = ip
                    break
        cisco[packet.src] = (pkg_addr,pref_ip)
    return cisco

if __name__ == "__main__":
    cdp = cdp_scan(all=True)
    for mac,ips in cdp.items():
        print(mac + " @ " + ', '.join(ips[0]) + ' (' + ips[1] + ')')

