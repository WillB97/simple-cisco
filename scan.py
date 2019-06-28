#! /usr/bin/env python3

def cdp_scan(all=False): ## add functionality to search for a mac address (stop_filter)
    from scapy.all import get_if_list, get_if_addr, load_contrib, sniff
    
    load_contrib("cdp")
    addr_list=[]
    cisco = {}

    for addr in get_if_list():
        ## adapt to limit interfaces to eth/wifi only
        if get_if_addr(addr) not in ['0.0.0.0', '127.0.0.1']: # ignore interfaces without ip addresses and localhost
            addr_list.append(addr)

    if all:
        p = sniff(iface=addr_list, timeout=60, filter="ether dst 01:00:0c:cc:cc:cc")
    else:
        p = sniff(iface=addr_list, timeout=60, count=1, filter="ether dst 01:00:0c:cc:cc:cc")

    for packet in p:
        try:
            cisco[packet.src] = packet['CDPAddrRecordIPv4'].addr
        except IndexError:
            try:
                if packet['CDPAddrRecordIPv6'].addr.startswith('fe80:'):
                    cisco[packet.src] = packet['CDPAddrRecordIPv6'].addr + '%' + packet.sniffed_on
                else:
                    cisco[packet.src] = packet['CDPAddrRecordIPv6'].addr
            except IndexError:
                cisco[packet.src] = 'no IP'
    return cisco

if __name__ == "__main__":
    cdp = cdp_scan(all=True)
    for mac,ip in cdp.items():
        print(mac + " @ " + ip)

