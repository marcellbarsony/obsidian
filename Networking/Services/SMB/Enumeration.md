---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMB/Enumeration
links: "[[SMB]]"
---

# Enumeration

___

<!-- Network {{{-->
## Network

Enumerate the target network for SMB-enabled hosts

[nbtscan](https://www.kali.org/tools/nbtscan/) —
Scan a network searching for SMB hosts

```sh
nbtscan -r <target_network>/<cidr>
```

<!-- Info {{{-->
> [!info]-
>
> - `-r`: Use local port `137` for scans
<!-- }}} -->

[[NetExec]] - [Map Network Hosts](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-hosts) —
Return a list of live hosts on the network

```sh
nxc smb <network_ip>/<cidr>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nxc smb 192.168.1.0/24
> ```
>
> ```sh
> SMB         192.168.1.101    445    DC2012A          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012A) (domain:OCEAN) (signing:True) (SMBv1:True)
> SMB         192.168.1.102    445    DC2012B          [*] Windows Server 2012 R2 Standard 9600 x64 (name:DC2012B) (domain:EARTH) (signing:True) (SMBv1:True)
> SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:OCEAN) (signing:True) (SMBv1:True)
> SMB         192.168.1.117    445    WIN10DESK1       [*] WIN10DESK1 x64 (name:WIN10DESK1) (domain:OCEAN) (signing:False) (SMBv1:True)
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Service {{{-->
## Service

Enumerate the identified SMB service on the target host

<!-- NetBIOS {{{-->
### NetBIOS

Enumerate NetBIOS name

[nbtscan](https://www.kali.org/tools/nbtscan/) —
Enumerate target hostname

```sh
nbtscan $target
```

[nmblookup](https://www.samba.org/samba/docs/current/man-html/nmblookup.1.html) —
NetBIOS over TCP/IP client to lookup NetBIOS names

```sh
nmblookup -A $target
```

<!-- }}} -->

<!-- Banner {{{-->
### Banner

Grab service banner

[[Nmap]] — Banner grabbing with default scripts

```sh
sudo nmap -sC -sV $target -p 139,445 -oA smb-default-scripts
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PORT    STATE SERVICE     VERSION
> 139/tcp open  netbios-ssn Samba smbd 4
> 445/tcp open  netbios-ssn Samba smbd 4
>
> Host script results:
> |_nbstat: NetBIOS name: DEVSMB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
> | smb2-security-mode:
> |   3:1:1:
> |_    Message signing enabled but not required
> | smb2-time:
> |   date: 2025-10-13T15:19:02
> |_  start_date: N/A
> ```
>
> > [!warning]
> >
> > May take a long time
<!-- }}} -->

<!-- }}} -->

<!-- Version {{{-->
### Version

Get SMB version

[[Metasploit]] - [smb_version](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_version/) —
SMB Version Detection

```sh
use auxiliary/scanner/smb/smb_version
```

<!-- Example {{{-->
> [!example]-
>
> Fingerprint and display version information about SMB servers
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/smb/smb_version
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 139
> ```
> ```sh
> run
> ```
> ```sh
> exit
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Host {{{-->
### Host

Enumerate OS/Host/Domain information

[[Nmap]] — Extract OS/Host/Domain information
(*[smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)*)

```sh
nmap $target -p 445 --script smb-os-discovery.nse -oA smb-os-discovery
```

<!-- }}} -->

<!-- Protocol {{{-->
### Protocol

Enumerate SMB protocols

[[Metasploit]] - [smb2](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb2/) —
SMB 2.0 Protocol Detection

```sh
use auxiliary/scanner/smb/smb2
```

<!-- Example {{{-->
> [!example]-
>
> Detect systems that support the SMB 2.0 protocol
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/smb/smb2
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 139
> ```
> ```sh
> run
> ```
<!-- }}} -->

[[Nmap]] — Discover SMB supported protocol features and dialects
(*[smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html)*)

```sh
nmap $target -p 445 --script smb-protocols -oA smb-protocols
```

<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

Execute all safe SMB enumeration scripts

[[Nmap]] — Run all `safe` and `smb-enum-*` scripts for non-destructive SMB enumeration

```sh
nmap $target -p 445 --script "safe or smb-enum-*" -oA smb-enumeration
```

[[Nmap]] — Run all `vuln*` scripts

```sh
sudo nmap $target -p 139,445 --script smb-vuln* -oA smb-scripts-vuln
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Anonymous Authentication {{{-->
## Anonymous Authentication

<!-- SMB Null Session {{{-->
### SMB Null Session

[SMB Null Session](https://hackviser.com/tactics/pentesting/services/smb#smb-null-session)
refers to an unauthenticated connection to an SMB server ^f374c7

[[NetExec]] — [Enumerate Null Sessions](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions)

```sh
nxc smb $target
```

```sh
nxc smb $target -u "" -p ""
```

[[Usage#smbclient|smbclient]] —
Enumerate SMB shares on the host
(*[Anonymous Null Session](https://hackviser.com/tactics/pentesting/services/smb#smb-null-session)*)

Connect to server and list share

```sh
smbclient -N -L //$target
```

```sh
smbclient -N -L //$target -U <user>
```

```sh
smbclient -N -L //$target --no-pass
```

```sh
smbclient -N -L //$target --user ''%''
```

```sh
smbclient -N //$target/ --option="client min protocol"=LANMAN1
```

<!-- Info {{{-->
> [!info]-
>
> - `-N`: Null session / Anonymous access
> - `-L`: List shares
> - `-U`: Specify user
> - `--no-pass`: Implicit null credentials
> - `--user ''%''`: Explicit null credentials
> - `--option="client min protocol"=LANMAN1`: Downgrade SMB dialect to
>   [LANMAN](https://en.wikipedia.org/wiki/LAN_Manager)
>   (*Legacy*)
<!-- }}} -->

Connect to server and list shares
(*Windows UNC path*)

```sh
smbclient -N -L \\\\$target\\
```

```sh
smbclient -N -L \\\\$target\\ -U <user>
```

```sh
smbclient -N -L \\\\$target\\ --no-pass
```

```sh
smbclient -N -L \\\\$target\\ --user ''%''
```

```sh
smbclient -N \\\\$target\\ --option="client min protocol"=LANMAN1
```

<!-- Info {{{-->
> [!info]-
>
> - `-N`: Null session / Anonymous access
> - `-L`: List shares
> - `-U`: Specify user
> - `--no-pass`: Implicit null credentials
> - `--option="client min protocol"=LANMAN1`: Downgrade SMB dialect to
>   [LANMAN](https://en.wikipedia.org/wiki/LAN_Manager)
>   (*Legacy*)
<!-- }}} -->

[SMBmap](https://github.com/ShawnDEvans/smbmap) —
Enumerate SMB shares and associated permissions on the host
(*[Anonymous Null Session](https://hackviser.com/tactics/pentesting/services/smb#smb-null-session)*)

<!-- Warning {{{-->
> [!warning]
>
> SMBmap is a detailed and aggressive automated script
<!-- }}} -->

```sh
smbmap -H $target
```

```sh
smbmap -H $target -u "" -p ""
```

```sh
smbmap -H $target -u null -p null
```

<!-- Info {{{-->
> [!info]-
>
> - `-H`: Specify the host IP
> - `-u ""`: Supply an empty username
> - `-p ""`: Supply an empty password
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smbmap -H 10.129.14.128
> ```
> ```sh
> [+] Finding open SMB ports....
> [+] User SMB session established on 10.129.14.128...
> [+] IP: 10.129.14.128:445       Name: 10.129.14.128
>         Disk                                                    Permissions     Comment
>         ----                                                    -----------     -------
>         print$                                                  NO ACCESS       Printer Drivers
>         home                                                    NO ACCESS       INFREIGHT Samba
>         dev                                                     NO ACCESS       DEVenv
>         notes                                                   NO ACCESS       CheckIT
>         IPC$                                                    NO ACCESS       IPC Service (DEVSM)
> ```
<!-- }}} -->

Browse directories recursively

```sh
smbmap -H $target -r <share>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smbmap -H 10.129.14.128 -r notes
> ```
> ```sh
> [+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
>         Disk                                                    Permissions     Comment
>         --                                                   ---------    -------
>         notes                                                   READ, WRITE
>         .\notes\*
>         dr--r--r               0 Mon Nov  2 00:57:44 2020    .
>         dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
>         dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
>         fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
>         fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
>         dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
>         dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
>         dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
> ```
<!-- }}} -->

<!-- }}} -->

<!-- SMB Guest Logon {{{-->
### SMB Guest Logon

Enumerate target SMB service for guest logon
via random username and password

[[NetExec]] — [Enumerate Guest Logon](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-guest-logon)

```sh
nxc smb $target -u 'a' -p ''
```

```sh
nxc smb $target -u "guest" -p ""
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nxc smb 10.10.10.178 -u 'a' -p ''
> ```
> ```sh
> nxc smb 10.10.10.178 -u 'a' -p '' --shares
> ```
<!-- }}} -->

[SMBmap](https://github.com/ShawnDEvans/smbmap) —
Enumerate SMB guest logon

```sh
smbmap -H $target -u guest
```

<!-- }}} -->

<!-- Enumeration {{{-->
### Enumeration

Enumerate disks on the target

[[NetExec]] — [Enumerate Disks](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-disks)

```sh
nxc smb $target --disks
```

```sh
nxc smb $target -u '' -p '' --disks
```

```sh
nxc smb $target -u 'guest' -p '' --disks
```

Enumerate groups on the target

[[NetExec]] — [Enumerate Local Groups](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-local-groups)

```sh
nxc smb $target --local-group
```

```sh
nxc smb $target -u '' -p '' --local-group
```

```sh
nxc smb $target -u 'guest' -p '' --local-group
```

Enumerate domain password policy

[[Netexec]] — [Enumerate Domain Password Policy](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-domain-password-policy-1)

```sh
nxc smb $target --pass-pol
```

```sh
nxc smb $target -u "" -p "" --pass-pol
```

```sh
nxc smb $target -u "guest" -p "" --pass-pol
```

Enumerate processes on the target

[[NetExec]] — [Enumerate Remote Processes](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-remote-processes)

```sh
nxc smb $target --tasklist
```

```sh
nxc smb $target -u '' -p '' --tasklist
```

```sh
nxc smb $target -u 'guest' -p '' --tasklist
```

Enumerate SMB shares on the target

[[NetExec]] — [Enumerate Shares and Access](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-shares-and-access)

```sh
nxc smb $target --shares
```

```sh
nxc smb $target -u "" -p "" --shares
```

```sh
nxc smb $target -u 'guest' -p '' --shares
```

[[Metasploit]] — [smb_enumshares](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_enumshares/) —
SMB Share Enumeration

```sh
use auxiliary/scanner/smb/smb_enumshares
```

<!-- }}} -->

___
<!-- }}} -->

<!-- CVE Exploits {{{-->
## CVE Exploits

<!-- Netapi {{{-->
### Netapi

Detect [[Exploitation#Netapi|Netapi]]
(*[MS08-067](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067)*)

[[Nmap]] —
[smb-vuln-ms08-067](https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html)

<!-- Warning {{{-->
> [!warning]
>
> This check is dangerous and it may crash systems
<!-- }}} -->

```sh
nmap $target -p 445 --script smb-vuln-ms08-067.nse -oA smb-netapi-tcp
```

```sh
nmap -sU $target -p U:137 --script smb-vuln-ms08-067.nse -oA smb-netapi-udp
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> | smb-vuln-ms08-067:
> |   VULNERABLE:
> |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
> |     State: VULNERABLE
> |     IDs:  CVE:CVE-2008-4250
> |           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
> |           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
> |           code via a crafted RPC request that triggers the overflow during path canonicalization.
> |
> |     Disclosure date: 2008-10-23
> |     References:
> |       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
> |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
> ```
<!-- }}} -->

<!-- }}} -->

<!-- EternalBlue {{{-->
### EternalBlue

Detect [[Exploitation#EternalBlue|EternalBlue]]
(*[MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)*)

[[Nmap]] —
[smb-vuln-ms17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html)

```sh
nmap -Pn <ip_netblock> -p 445 --open --max-hostgroup 3 --script smb-vuln-ms17-010  -oA smb-eternalblue
```

```sh
nmap -A $target -p 445
```

<!-- Info {{{-->
> [!info]-
>
> - `-Pn`: Skip ping check, treat hosts as online
> - `--max-hostgroup 3`: Limit the number of parallel hosts scanned
> - `<ip_netblock>`: Target IP range/subnet (e.g. `192.168.1.0/24`)
> - `-A`: Enable OS detection, version detection, script scanning, and traceroute
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> Host script results:
> | smb-vuln-ms17-010:
> |   VULNERABLE:
> |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
> |     State: VULNERABLE
> |     IDs:  CVE:CVE-2017-0143
> |     Risk factor: HIGH
> |       A critical remote code execution vulnerability exists in Microsoft SMBv1
> |        servers (ms17-010).
> |
> |     Disclosure date: 2017-03-14
> |     References:
> |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
> |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
> |_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
> ```
<!-- }}} -->

[[NetExec]] —
[Scan for MS17-010](https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities#ms17-010-not-tested-outside-lab-environment)

> [!warning]
>
> Not tested outside LAB environment

```sh
nxc smb $target -u '' -p '' -M ms17-010
```

<!-- }}} -->

<!-- SMBGhost {{{-->
### SMBGhost

Detect [[Exploitation#SMBGhost|SMBGhost]]
(*[CVE-2020-0796](https://nvd.nist.gov/vuln/detail/cve-2020-0796)*)

[[Netexec]] - [Scan for SMBGhost](https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities#smbghost)

```sh
nxc smb $target -u '' -p '' -M smbghost
```

```sh
nxc smb $target -u 'guest' -p '' -M smbghost
```


<!-- }}} -->

<!-- ZeroLogon {{{-->
### ZeroLogon

Detect [[Exploitation#ZeroLogon|ZeroLogon]]
(*[CVE-2020-1472](https://nvd.nist.gov/vuln/detail/cve-2020-1472)*)

> [!warning]
>
> Affects [[Domain Controller|Domain Controllers]] only

[[NetExec]] - [Scan for ZeroLogon](https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities#zerologon)

```sh
nxc smb <ip> -u '' -p '' -M zerologon
```

<!-- }}} -->

___
<!-- }}} -->

<!-- IPC$ Share {{{-->
## IPC$ Share

Remote Procedure Call ([[Services/SMB/General#RPC|RPC]])
Enumeration through anonymous null session

[RPCclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) —
Connect to an IPC$ share to test MS-RPC functionality in Samba
(*[SMB Null Session](https://hackviser.com/tactics/pentesting/services/smb#smb-null-session)*)

```sh
rpcclient $target
```

```sh
rpcclient -U "" $target
```

```sh
rpcclient -U "%" $target
```

```sh
rpcclient -N -U "" $target
```

```sh
rpcclient -N -U "" $target -L
```

```sh
rpcclient -N -U "%" $target
```

```sh
rpcclient -N -U "%" $target -L
```

```sh
rpcclient -U "username%password" $target
```

<!-- Info {{{-->
> [!info]-
>
> - `-N` / `--no-pass`: Suppress the normal password prompt
> - `-U`: Set SMB username and password
> - `-L`: List shares
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> rpcclient -U "" 10.129.244.136
> ```
>
> Press `Enter` to bypass the password prompt
>
> ```sh
> Enter WORKGROUP\'s password:
> rpcclient $>
> ```
>
> ```sh
> rpcclient $> enumdomusers
> ```
>
> ```sh
> user:[mhope] rid:[0x641]
> user:[svc-ata] rid:[0xa2b]
> user:[svc-bexec] rid:[0xa2c]
> user:[roleary] rid:[0xa36]
> user:[smorgan] rid:[0xa37]
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Automated Scripts {{{-->
## Automated Scripts

**ENUM4LINUX**

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
is a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient`
and [[Usage#smbclient|smbclient]] that interacts with the exposed services
via [named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes)

1. Clone the [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
   repository

```sh
git clone https://github.com/cddmp/enum4linux-ng.git && cd enum4linux-ng
```

2. Initialize [[Python]] [[Virtual Environment]]

3. Install requirements

```sh
pip3 install -r requirements.txt
```

2. Enumerate SMB host

```sh
./enum4linux-ng.py $target -A -C
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./enum4linux-ng.py 10.129.14.128 -A
> ```
> ```sh
> ENUM4LINUX - next generation
>
>  ==========================
> |    Target Information    |
>  ==========================
> [*] Target ........... 10.129.14.128
> [*] Username ......... ''
> [*] Random Username .. 'juzgtcsu'
> [*] Password ......... ''
> [*] Timeout .......... 5 second(s)
>
>  =====================================
> |    Service Scan on 10.129.14.128    |
>  =====================================
> [*] Checking LDAP
> [-] Could not connect to LDAP on 389/tcp: connection refused
> [*] Checking LDAPS
> [-] Could not connect to LDAPS on 636/tcp: connection refused
> [*] Checking SMB
> [+] SMB is accessible on 445/tcp
> [*] Checking SMB over NetBIOS
> [+] SMB over NetBIOS is accessible on 139/tcp
>
>  =====================================================
> |    NetBIOS Names and Workgroup for 10.129.14.128    |
>  =====================================================
> [+] Got domain/workgroup name: DEVOPS
> [+] Full NetBIOS names information:
> - DEVSMB          <00> -         H <ACTIVE>  Workstation Service
> - DEVSMB          <03> -         H <ACTIVE>  Messenger Service
> - DEVSMB          <20> -         H <ACTIVE>  File Server Service
> - ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
> - DEVOPS          <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
> - DEVOPS          <1d> -         H <ACTIVE>  Master Browser
> - DEVOPS          <1e> - <GROUP> H <ACTIVE>  Browser Service Elections
> - MAC Address = 00-00-00-00-00-00
>
>  ==========================================
> |    SMB Dialect Check on 10.129.14.128    |
>  ==========================================
> [*] Trying on 445/tcp
> [+] Supported dialects and settings:
> SMB 1.0: false
> SMB 2.02: true
> SMB 2.1: true
> SMB 3.0: true
> SMB1 only: false
> Preferred dialect: SMB 3.0
> SMB signing required: false
>
>  ==========================================
> |    RPC Session Check on 10.129.14.128    |
>  ==========================================
> [*] Check for null session
> [+] Server allows session using username '', password ''
> [*] Check for random user session
> [+] Server allows session using username 'juzgtcsu', password ''
> [H] Rerunning enumeration with user 'juzgtcsu' might give more results
>
>  ====================================================
> |    Domain Information via RPC for 10.129.14.128    |
>  ====================================================
> [+] Domain: DEVOPS
> [+] SID: NULL SID
> [+] Host is part of a workgroup (not a domain)
>
>  ============================================================
> |    Domain Information via SMB session for 10.129.14.128    |
>  ============================================================
> [*] Enumerating via unauthenticated SMB session on 445/tcp
> [+] Found domain information via SMB
> NetBIOS computer name: DEVSMB
> NetBIOS domain name: ''
> DNS domain: ''
> FQDN: htb
>
>  ================================================
> |    OS Information via RPC for 10.129.14.128    |
>  ================================================
> [*] Enumerating via unauthenticated SMB session on 445/tcp
> [+] Found OS information via SMB
> [*] Enumerating via 'srvinfo'
> [+] Found OS information via 'srvinfo'
> [+] After merging OS information we have the following result:
> OS: Windows 7, Windows Server 2008 R2
> OS version: '6.1'
> OS release: ''
> OS build: '0'
> Native OS: not supported
> Native LAN manager: not supported
> Platform id: '500'
> Server type: '0x809a03'
> Server type string: Wk Sv PrQ Unx NT SNT DEVSM
>
>  ======================================
> |    Users via RPC on 10.129.14.128    |
>  ======================================
> [*] Enumerating users via 'querydispinfo'
> [+] Found 2 users via 'querydispinfo'
> [*] Enumerating users via 'enumdomusers'
> [+] Found 2 users via 'enumdomusers'
> [+] After merging user results we have 2 users total:
> '1000':
>   username: mrb3n
>   name: ''
>   acb: '0x00000010'
>   description: ''
> '1001':
>   username: cry0l1t3
>   name: cry0l1t3
>   acb: '0x00000014'
>   description: ''
>
>  =======================================
> |    Groups via RPC on 10.129.14.128    |
>  =======================================
> [*] Enumerating local groups
> [+] Found 0 group(s) via 'enumalsgroups domain'
> [*] Enumerating builtin groups
> [+] Found 0 group(s) via 'enumalsgroups builtin'
> [*] Enumerating domain groups
> [+] Found 0 group(s) via 'enumdomgroups'
>
>  =======================================
> |    Shares via RPC on 10.129.14.128    |
>  =======================================
> [*] Enumerating shares
> [+] Found 5 share(s):
> IPC$:
>   comment: IPC Service (DEVSM)
>   type: IPC
> dev:
>   comment: DEVenv
>   type: Disk
> home:
>   comment: INFREIGHT Samba
>   type: Disk
> notes:
>   comment: CheckIT
>   type: Disk
> print$:
>   comment: Printer Drivers
>   type: Disk
> [*] Testing share IPC$
> [-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
> [*] Testing share dev
> [-] Share doesn't exist
> [*] Testing share home
> [+] Mapping: OK, Listing: OK
> [*] Testing share notes
> [+] Mapping: OK, Listing: OK
> [*] Testing share print$
> [+] Mapping: DENIED, Listing: N/A
>
>  ==========================================
> |    Policies via RPC for 10.129.14.128    |
>  ==========================================
> [*] Trying port 445/tcp
> [+] Found policy:
> domain_password_information:
>   pw_history_length: None
>   min_pw_length: 5
>   min_pw_age: none
>   max_pw_age: 49710 days 6 hours 21 minutes
>   pw_properties:
>   - DOMAIN_PASSWORD_COMPLEX: false
>   - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
>   - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
>   - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
>   - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
>   - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
> domain_lockout_information:
>   lockout_observation_window: 30 minutes
>   lockout_duration: 30 minutes
>   lockout_threshold: None
> domain_logoff_information:
>   force_logoff_time: 49710 days 6 hours 21 minutes
>
>  ==========================================
> |    Printers via RPC for 10.129.14.128    |
>  ==========================================
> [+] No printers returned (this is not an error)
>
> Completed after 0.61 seconds
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning] Deprecated
>
> Dump interesting information
>
> ```sh
> enum4linux -a [-u "<user>" -p "<password>"] $target
> ```
>
> ```sh
> enum4linux-ng -A [-u "<user>" -p "<password>"] $target
> ```
<!-- }}} -->

**ADDITIONAL SCRIPTS**

Grab SMB server version

<!-- Info {{{-->
> [!info]
>
> [tcpdump](https://www.tcpdump.org/)
> requires root permissions
>
> [tcpdump](https://www.tcpdump.org/)
> will listen for the first 7 packets of a null login
> and grab the SMB Version
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> **Grab SMB server version**
>
> ```sh
> #!/bin/sh
> # Author: rewardone
>
> if [ -z $1 ]; then \
>     echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; \
> else \
>     rhost=$1; \
> fi
> if [ ! -z $2 ]; then \
>     rport=$2; \
> else \
>     rport=139; \
> fi
> tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " &
> echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
> echo "" && sleep .1
> ```
>
> > [!warning]
> >
> > Will sometimes not capture or will print multiple lines
> >
> > May need to run a second time for success
<!-- }}} -->

___
<!-- }}} -->
