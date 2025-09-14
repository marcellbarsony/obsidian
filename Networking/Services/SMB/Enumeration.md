---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMB/Enumeration
links: "[[SMB]]"
---

# Enumeration

## Port 445

### nbtscan

Scan a network searching for hosts via [nbtscan](https://www.kali.org/tools/nbtscan/)

```sh
nbtscan -r <ip>/24
```

### Nmap scripts

Enumerate SMB with [[Nmap]] scripts (e.g. [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html))

```sh
nmap --script smb-os-discovery.nse -p445 10.10.10.40
```

### Scripts

Grab SMB server version

```sh
#!/bin/sh
# Author:
# rewardone
#
# Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#
# Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
#
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1
```
