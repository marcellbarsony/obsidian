---
id: SMB
aliases:
  - Server Message Block
tags:
  - SMB
links: "[[Services]]"
---

# Server Message Block (SMB)

The **Server Message Block (SMB)** protocol, operating in a client-server model,
is designed for sharing files, directories, and other resources like printers
and routers over a network.

## Port 139

The **Network Basic Input Output System (NetBIOS)** is a software protocol
designed to enable applications, PCs, and Desktops within a local area network
(LAN) to interact with network hardware and facilitate the transmission of data
across the network.

## Port 445

<!-- Enumeration {{{-->
### Enumeration

Scan a network searching for hosts

```sh
nbtscan -r <ip>/24
```

SMB server version

```sh
#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi
if [ ! -z $2 ]; then rport=$2; else rport=139; fi
tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo "" && sleep .1
```

Search for exploits with Metasploit

```sh
msf> search type:exploit platform:windows target:2008 smb
searchsploit microsoft smb
```
<!-- }}} -->

<!-- Connection {{{-->
### Connection

#### Linux

Connect to an anonymous share

```sh
smbclient //{target_ip}/anonymous
```

#### Windows (UNC path)

Discover & connect to shares (Windows UNC path)

```sh
smbclient -N -L \\\\{target_ip}\\
```

Connect to a share

```sh
smbclient -N \\\\{target_ip}\\{share}
```
<!-- }}} -->

<!-- Attack vectors {{{-->
### Attack vectors

#### Brute force

Brute force SMB login

```
nmap --script smb-brute -p 445 <ip>
hydra -l {target_user} -P {password_list} {target_ip} smb -t 1
```
<!-- }}} -->

<!-- Post-Exploitation {{{-->
### Post-Exploitation

```sh
# Change directory
smb: \> cd

# List files
smb: \> dir

# Get file
smb: \> get <remote file name> [local file name]

# Exit
smb: \> exit
```
<!-- }}} -->
