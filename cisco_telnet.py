#! /usr/bin/env python3
import telnetlib
import re

class Cisco():
    def __init__(self, host, password):
        self.host = host
        self.password = password
        self.tn = telnetlib.Telnet(host,timeout=3)
        print('Connection Established')
        self.hostname = self.login(password)
        print('Login to "{}" Completed'.format(self.hostname))

    def login(self, password, username='Cisco'):
        text = self.tn.read_until(b':')
        if text.endswith(b'Username:'):
            self.tn.write(username.encode('ascii') + b'\n')
            self.tn.read_until(b'Password:')
        self.tn.write(password.encode('ascii') + b'\n')
        text_tup = self.tn.expect([b':',b'>',b'#'])
        if b':' == text_tup[1][0]: # incorrect password
            self.tn.close # close connection
            raise ValueError('Invalid Login Credentials')
        elif b'#' == text_tup[1][0]:
            self.tn.write(b'config?')
            text = self.tn.read_until(b'#')
            if b'%' not in text:
                self.tn.write(b'\x1B\x7F') # clear line (ESC BKSP)
                self.tn.read_very_eager()
                self.run_command('terminal length 0')
                return re.search(r'^(.*)#$',text_tup[2].decode('ascii'),re.MULTILINE).groups()[0]
        self.tn.write(b'enable\n')
        self.tn.read_until(b'Password:')
        self.tn.write(password.encode('ascii') + b'\n')
        text_tup = self.tn.expect([b':',b'#']) # confirm correct password
        if b':' == text_tup[1][0]: # incorrect password
            # Cancel password entry (newlines until prompt received)
            while text_tup[1][0] == b':':
                self.tn.write(b'\n')
                text_tup = self.tn.expect([b':',b'#',b'>'])
            self.tn.write(b'exit\n')
            raise ValueError('Invalid Enable Password')
        self.run_command('terminal length 0')
        return re.search(r'^(.*)#$',text_tup[2].decode('ascii'),re.MULTILINE).groups()[0]

    def config(self):
        self.run_command('config terminal')

    def run_command(self, cmd, autoreconnect=False):
        self.tn.write(cmd.encode('ascii') + b'\n')
        res = self.tn.read_until(b'#',3)
        if b'\n%' in res: # detect errors
            e = re.search(r'^(%.*)\r$', res.decode('ascii'), re.MULTILINE).groups()[0]
            raise ValueError(e)
        if autoreconnect and not res.endswith(b'#'): # handle new IP requiring a reconnection
            self.tn.close()
            self.tn.open(self.host)
            self.hostname = self.login(self.password)
            print('Connection re-established to "{}"'.format(self.hostname))
            self.config()
        return res.decode('ascii').splitlines()[1:-1]

    def run_command_confirm(self, cmd):
        self.tn.write(cmd.encode('ascii') + b'\n')
        res_tup = self.tn.expect([b'\[confirm\]',b'#'])
        res = res_tup[2]
        if res_tup[1][0] == b'[confirm]':
            self.tn.write(b'y')
            res += self.tn.read_until(b'#',0.5)
        if b'\n%' in res: # detect errors
            e = re.search(r'^(%.*)\r$', res.decode('ascii'), re.MULTILINE).groups()[0]
            raise ValueError(e)

    def save_and_exit(self, batch=False):
        self.run_command('end')
        self.run_command('write')
        if not batch:
            self.run_command('exit')

    def initialise(self, new_password, new_addr='dhcp', batch=False):
        try:
            self.config()
            self.run_command('interface bvi 1')
            if new_addr != 'dhcp':
                self.run_command('ip address ' + new_addr + ' 255.255.255.0')
                print('New Management IP {} set'.format(new_addr))
                self.host = new_addr
            else:
                self.run_command('ip address dhcp')
                print('Management IP set to DHCP')
            self.run_command('exit', autoreconnect=True) # handle new IP requiring a reconnection
            self.run_command('interface dot11Radio 0')
            self.run_command('encryption mode ciphers aes-ccm')
            self.run_command('speed range') # configure for maximum range
            print('Enabled encryption on 2.4GHz radio')
            self.run_command('exit')
            self.run_command('interface dot11Radio 1')
            self.run_command('encryption mode ciphers aes-ccm')
            self.run_command('speed range') # configure for maximum range
            print('Enabled encryption on 5GHz radio')
            self.run_command('exit')
            self.run_command('enable secret 0 ' + new_password.replace('?',b'\x16?'.decode('ascii'))) # replace '?' with ^V?
            print('Enable password updated')
            self.run_command('username Cisco privilege 15 password 0 ' + new_password.replace('?',b'\x16?'.decode('ascii')))  # replace '?' with ^V?
            print('User password updated')
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)
        print('Initialisation complete')
        self.password = new_password

    def wifi_enable(self, batch=False):
        try:
            self.config()
            self.run_command('interface dot11Radio 0')
            self.run_command('no shutdown')
            print('2.4GHz radio enabled')
            self.run_command('exit')
            self.run_command('interface dot11Radio 1')
            self.run_command('no shutdown')
            print('5GHz radio enabled')
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def wifi_disable(self, batch=False):
        try:
            self.config()
            self.run_command('interface dot11Radio 0')
            self.run_command('shutdown')
            print('2.4GHz radio disabled')
            self.run_command('exit')
            self.run_command('interface dot11Radio 1')
            self.run_command('shutdown')
            print('5GHz radio disabled')
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def wifi_clear(self, batch=False):
        try:
            ssids_raw = self.run_command('show running-config brief | include ssid')
            ssids = []
            for ssid_raw in ssids_raw:
                ssid = re.search(r'^\s*dot11\s+ssid\s+(.*)$', ssid_raw)
                if ssid:
                    ssids.append(ssid.groups()[0])
            self.config()
            for ssid in ssids:
                self.run_command('no dot11 ssid ' + ssid)
                print('Removed ' + ssid)
            self.save_and_exit(batch)
            print('Cleared all SSIDs')
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def wifi_ssid(self, ssid_2=None, psk_2=None, ssid_5=None, psk_5=None, batch=False):
        try:
            self.config()
            if ssid_2:
                self.run_command('dot11 ssid ' + ssid_2.replace('?',b'\x16?'.decode('ascii')))  # replace '?' with ^V?
                self.run_command('authentication open')
                self.run_command('authentication key-management wpa version 2')
                self.run_command('wpa-psk ascii ' + psk_2.replace('?',b'\x16?'.decode('ascii'))) # replace '?' with ^V?
                self.run_command('guest-mode')
                self.run_command('exit')
                self.run_command('interface dot11Radio 0')
                warns = self.run_command('ssid ' + ssid_2)
                if warns: # handle an ssid already being bound
                    old_ssid = re.search(r'on ssid (.*)$',warns[0])
                    if not old_ssid:
                        raise ValueError('Error occurred while setting SSID\n' + warns)
                    self.run_command('no ssid '+ old_ssid.group(1))
                    self.run_command('ssid ' + ssid_2)
                self.run_command('no shutdown')
                print('Added SSID "{}" on 2.4GHz Radio'.format(ssid_2))
            if ssid_5:
                if ssid_2 != ssid_5:
                    self.run_command('dot11 ssid ' + ssid_5.replace('?',b'\x16?'.decode('ascii')))  # replace '?' with ^V?
                    self.run_command('authentication open')
                    self.run_command('authentication key-management wpa version 2')
                    self.run_command('wpa-psk ascii ' + psk_5.replace('?',b'\x16?'.decode('ascii'))) # replace '?' with ^V?
                    self.run_command('guest-mode')
                    self.run_command('exit')
                self.run_command('interface dot11Radio 1')
                warns = self.run_command('ssid ' + ssid_5)
                if warns: # handle an ssid already being bound
                    old_ssid = re.search(r'on ssid (.*)$',warns[0])
                    if not old_ssid:
                        raise ValueError('Error occurred while setting SSID\n' + warns)
                    self.run_command('no ssid '+ old_ssid.group(1))
                    self.run_command('ssid ' + ssid_5)
                self.run_command('no shutdown')
                print('Added SSID "{}" on 5GHz Radio'.format(ssid_5))
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def led_enable(self, batch=False):
        try:
            self.config()
            self.run_command('no led display off')
            self.save_and_exit(batch)
            print('LED enabled')
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def led_disable(self, batch=False):
        try:
            self.config()
            self.run_command('led display off')
            self.save_and_exit(batch)
            print('LED disabled')
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def dhcp(self, start, end, batch=False):
        start_addr = int(start)
        end_addr = int(end)
        if start_addr not in range(255) or end_addr not in range(255):
            raise ValueError('Start and end values must be in the range 0 to 255')
        if end_addr <= start_addr:
            raise ValueError('Start value must be lower than the end value')
        try:
            if_addr = self.run_command('show ip interface bvI 1 | include Internet') # get interface IP for network address
            self.config()
            self.run_command('ip dhcp pool 0')
            if_list = if_addr[0].split()[3].split('.')
            net_prefix = if_list[0] + '.' + if_list[1] + '.' + if_list[2]
            self.run_command('network ' + net_prefix + '.0 /24')
            self.run_command('lease 10')
            self.run_command('class class1')
            self.run_command('address range ' + net_prefix + '.' + str(start_addr) + ' ' + net_prefix + '.' + str(end_addr))
            print('DHCP server started for {0}.{1} - {0}.{2}'.format(net_prefix,start_addr,end_addr))
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def dhcp_off(self, batch=False):
        try:
            self.config()
            try:
                self.run_command('no ip dhcp pool 0')
                self.run_command('no ip dhcp class class1')
                print('DHCP pool removed')
            except ValueError:
                print('DHCP pool was not configured')
            self.save_and_exit(batch)
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)

    def reset(self, keep_ip=True, batch=False):
        try:
            self.run_command('write memory')
            if keep_ip:
                self.run_command_confirm('write erase')
            else:
                self.run_command_confirm('write default-config')
            self.run_command_confirm('reload')
        except EOFError:
            print('Telnet connection closed unexpectedly')
            exit(1)
        print('Reset complete, AP rebooting')

if __name__ == "__main__":
    from time import sleep
    conn = Cisco(host='fe80::207:7dff:fe80:64ac%en4',password='Cisco')
    # conn.tn.set_debuglevel(2)
    conn.initialise(new_password='Cisco123', new_addr='192.168.2.2', batch=True)
    conn.wifi_ssid(ssid_2='+', psk_2='youlikejazz?', ssid_5='+', psk_5='youlikejazz?', batch=True)
    conn.led_disable(batch=True)
    conn.run_command('exit')

    sleep(10)

    conn2 = Cisco(host='192.168.2.2',password='Cisco123')
    # conn2.tn.set_debuglevel(1)
    conn2.wifi_disable(batch=True)
    conn2.led_enable(batch=True)

    sleep(30)

    conn2.wifi_enable(batch=True)
    conn2.wifi_clear(batch=True)
    conn2.run_command('terminal length 0')
    config = conn2.run_command('show run')
    for line in config:
        print(line)
    conn2.run_command('exit')
