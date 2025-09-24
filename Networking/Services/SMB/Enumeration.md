---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMB/Enumeration
links: "[[SMB]]"
---

# Enumeration

<!-- Nmap {{{-->
## Nmap

Nmap script scan the Samba server (*may take a long time*)

```sh
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
<!-- }}} -->

<!-- RPCclient {{{-->
## RPCclient

The **Remote Procedure Call** [RPC](https://www.geeksforgeeks.org/operating-systems/remote-procedure-call-rpc-in-operating-system/)
is a concept and tool to realize operational and work-sharing structures in
networks and client-server architectures.

```sh
rpcclient -U "" 10.129.14.128
```
```sh
Enter WORKGROUP\'s password:
rpcclient $>
```

### Enumeration

Query server information

```sh
rpcclient $> srvinfo
```

Enumerate all deployed domains

```sh
rpcclient $> enumdomains
```

Get domain, server and user information

```sh
rpcclient $> querydominfo
```

Enumerate all available shares

```sh
rpcclient $> netshareenumall
```

Get info about specific share (e.g., `notes`)

```sh
rpcclient $> netsharegetinfo notes
```

### User Enumeration

Enumerate all domain users & get their `RID`

```sh
rpcclient $> enumdomusers
```

Enumerate user information by `RID`

```sh
rpcclient $> queryuser 0x3e9
```

#### Brute Force User RIDs

Brute force User `RID`s using `rpcclient`

```sh
for i in $(seq 500 1100); do \
    rpcclient -N -U "" <target_ip> \
    -c "queryuser 0x$(printf '%x\n' $i)" | \
    grep "User Name\|user_rid\|group_rid" && \
    echo ""; \
done
```

Brute force User RIDs using [samrdump.py](https://github.com/fortra/impacket/blob/master/examples/samrdump.py)
(from [Impacket](https://github.com/fortra/impacket))

```sh
samrdump.py <target_ip>
```

### Group Information

Enumerate group information by `RID` (*acquired from user information*)

```sh
rpcclient $> querygroup 0x201
```
<!-- }}} -->

<!-- SMBmap {{{-->
## SMBmap

[SMBmap](https://github.com/ShawnDEvans/smbmap) -
Enumerate SMB shares on the host, using *anonymous* access with

```sh
smbmap -H <target_ip>
```
<!-- }}} -->

<!-- CrackMapExec {{{-->
## CrackMapExec

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (*deprecated*) -
Enumerate SMB shares on the host, using *anonymous* access

```sh
crackmapexec smb <target_ip> --shares -u '' -p ''
```
<!-- }}} -->

<!-- Enum4Linux-ng {{{-->
## Enum4Linux-ng

Install [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

```sh
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```

Enumerate SMB host

```sh
./enum4linux-ng.py <target_ip> -A
```
<!-- }}} -->

<!-- Port 445 {{{-->
## Port 445

### nbtscan

[nbtscan](https://www.kali.org/tools/nbtscan/) -
Scan a network searching for hosts via

```sh
nbtscan -r <target_network>/24
```

### Nmap scripts

Enumerate SMB with [[Nmap]] scripts (e.g. [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html))

```sh
nmap --script smb-os-discovery.nse -p445 <target_ip>
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
<!-- }}} -->
