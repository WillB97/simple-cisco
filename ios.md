#### init
```
enable
config t
interface bvi 1
ip address <address> 255.255.255.0


enable
config t
interface dot11Radio 0
encryption mode ciphers aes-ccm
exit
interface dot11Radio 1
encryption mode ciphers aes-ccm
exit
enable secret <password>
username Cisco privilege 15 password <password>
exit
write
```

#### wifi off|[on]
```
enable
config t
interface dot11Radio 0
[no] shutdown
exit
interface dot11Radio 1
[no] shutdown
end
write
exit
```

#### wifi --ssid
```
enable
config t
dot11 ssid <ssid>
authentication open
authentication key-management wpa version 2
wpa-psk ascii <passphrase>
guest-mode
exit
```
for 5GHz
```
interface dot11Radio 1
ssid <ssid>
no shutdown
```
for 2.4GHz
```
interface dot11Radio 0
ssid <ssid>
no shutdown
```

```
end
write
exit
```

#### wifi clear
```
enable
! get current ssid
show dot11 bssid
! clear all configured ssids
config y
no dot11 ssid <ssid>
end
write
exit
```

#### led on|off
```
enable
config t
[no] led display off
end
write
exit
```

#### Factory Reset
all
```
enable
write memory
write default-config
y
reload
y
```

except IP
```
enable
write memory
write erase
y
reload
y
```

#### dhcp
enable
```
enable
config t
! the ip address of the ap must be excluded
ip dhcp excluded-address <ap-address>
ip dhcp pool <name>
network <network address> /24
lease <days>|<hours> hours| infinite
address range <start> <end>
end
write
exit
```

disable
```
enable
config t
no ip dhcp pool
```

#### login types

<table>
<tr><th>Default (privilege 1)</th>
<th>privilege 15</th>
<th>privilege 2-14</th>
<th>vty password</th>
</tr>
<tr>
<td>
<pre>

User Access Verification

[Username: Cisco
Password:
% Login invalid
]
Username: Cisco
Password:
ap>enable
Password:
[Password:]
ap#
</pre></td>
<td><pre>
User Access Verification

[Username: Cisco
Password:
% Login invalid
]
Username: Cisco
Password:
ap#
</pre></td>
<td><pre>
User Access Verification

[Username: Cisco
Password:
% Login invalid
]
Username: Cisco
Password:
ap#config t
      ^
% Invalid input detected at '^' marker.

ap#enable
Password:
[Password:]
ap#config t
Enter configuration commands, one per line.  End with CNTL/Z.
ap(config)#
</pre></td>
<td><pre>
User Access Verification

Password:
ap>enable
Password:
[Password:]
ap#
</pre></td>
</tr></table>

Login:
- read_until(':')
- if endswith('Username:')
    - write('Cisco')
    - read_until('Password:')
- write(password)
- expect([':','>','#'])
- if ':' # confirm correct password
    - ... # incorrect password
    - close connection
    - return False
- if '#'
    - write('config?')
    - text = read_until('#')
    - if '%' not in text
        - clear line (ESC BKSP)
        - return True
- write('enable')
- read_until('Password:')
- write(password)
- expect([':','#']) # confirm correct password
- if ':'
    - ... # incorrect password
    - escape?
    - write('exit')
    - return False
- return True

