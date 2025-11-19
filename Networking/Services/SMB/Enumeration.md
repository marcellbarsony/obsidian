---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMB/Enumeration
links: "[[SMB]]"
---

# Enumeration

___

<!-- nbtscan {{{-->
## nbtscan

[nbtscan](https://www.kali.org/tools/nbtscan/) —
Scan a network searching for SMB hosts

```sh
nbtscan -r <target_network>/<cidr>
```

> [!info]-
>
> - `-r`: Use local port 137 for scans

___
<!-- }}} -->

<!-- Service {{{-->
## Service

[[Nmap]] — Scan [[SMB/General|SMB]] service

Banner grabbing with default scripts

```sh
sudo nmap -sV -sC <target> -p 139,445 -oA smb-default-scripts
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

Discover SMB versions and supported protocol features
(*[smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html)*)

```sh
nmap <target> -p 445 --script smb-protocols -oA smb-protocols
```

Extract OS/Host/Domain information
(*[smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)*)

```sh
nmap <target> -p 445 --script smb-os-discovery.nse -oA smb-os-discovery
```

Run all `safe` and `smb-enum-*` scripts for non-destructive SMB enumeration

```sh
nmap <target> -p 445 --script "safe or smb-enum-*" -oA smb-enumeration
```
___
<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

Scan [[SMB/General|SMB]] service with [[Metasploit]]

[smb_version](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_version/)
— SMB Version Detection

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
> set RHOSTS <target_ip>
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

[smb2](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb2/)
— SMB 2.0 Protocol Detection

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
> set RHOSTS <target_ip>
> ```
> ```sh
> set RPORT 139
> ```
> ```sh
> run
> ```
<!-- }}} -->

[smb_enumshares](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_enumshares/)
— SMB Share Enumeration

```sh
use auxiliary/scanner/smb/smb_enumshares
```

<!-- Example {{{-->
> [!example]-
>
> Determine what shares are provided by the SMB service,
> which ones are readable/writable and collect additional information
> (*e.g., share types, directories, files, time stamps, etc.*)
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/smb/smb_version
> ```
> ```sh
> set RHOSTS <target_ip>
> ```
> ```sh
> set RPORT 445
> ```
> ```sh
> run
> ```
<!-- }}} -->

[smb_enumusers](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_enumusers/)
— SMB User Enumeration (*SAM EnumUsers*)

```sh
use auxiliary/scanner/smb/smb_enumusers
```

<!-- Example {{{-->
> [!example]-
>
> Determine what users exist via the SAM RPC service
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/smb/smb_enumusers
> ```
> ```sh
> set RHOSTS <target_ip>
> ```
> ```sh
> set RPORT 445
> ```
> ```sh
> run
> ```
<!-- }}} -->

[smb_lookupsid](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_lookupsid/)
— SMB SID User Enumeration (*LookupSid*)

```sh
use auxiliary/scanner/smb/smb_lookupsid
```

<!-- Example {{{-->
> [!example]-
>
> Determine what users exist via brute force SID lookups.
> Enumerate both local and domain accounts by setting `ACTION`
> to either `LOCAL` or `DOMAIN`
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/smb/smb_lookupsid
> ```
> ```sh
> set RHOSTS <target_ip>
> ```
> ```sh
> set RPORT 445
> ```
> ```sh
> run
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- CVE Exploits {{{-->
## CVE Exploits

<!-- Netapi {{{-->
### Netapi

Detect [[Enumeration#Netapi|Netapi (MS08-067)]]
(*[smb-vuln-ms08-067](https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html)*)

> [!warning]
>
> This check is dangerous and it may crash systems


```sh
nmap <target> -p 445 --script smb-vuln-ms08-067.nse -oA smb-netapi-tcp
```

```sh
nmap -sU <target> -p U:137 --script smb-vuln-ms08-067.nse -oA smb-netapi-udp
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

Detect [[Enumeration#EternalBlue|EternalBlue (MS17-010)]]
(*[smb-vuln-ms17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html)*)

```sh
nmap -Pn <ip_netblock> -p 445 --open --max-hostgroup 3 --script smb-vuln-ms17-010  -oA smb-eternalblue
```

```sh
nmap -A <target> -p 445
```

> [!info]-
>
> - `-Pn`: Skip ping check, treat hosts as online
> - `--max-hostgroup 3`: Limit the number of parallel hosts scanned
> - `<ip_netblock>`: Target IP range/subnet (e.g. `192.168.1.0/24`)
> - `-A`: Enable OS detection, version detection, script scanning, and traceroute

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

<!-- }}} -->

___
<!-- }}} -->

<!-- Automated Scripts {{{-->
## Automated Scripts

<!-- Enum4Linux-ng {{{-->
### Enum4Linux-ng

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
a wrapper around the Samba tools `nmblookup`, `net`, `rpcclient`
and `smbclient` that interacts with the exposed services via named pipes

1. Install [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> git clone https://github.com/cddmp/enum4linux-ng.git
> ```
> ```sh
> cd enum4linux-ng
> ```
> ```sh
> pip3 install -r requirements.txt
> ```
<!-- }}} -->

2. Enumerate SMB host

```sh
./enum4linux-ng.py <target> -A
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
> [!warning]-
>
> **DEPRECATED**: Dump interesting information
>
>```sh
>enum4linux -a [-u "<username>" -p "<password>"] <target>
>```
>
>```sh
>enum4linux-ng -A [-u "<username>" -p "<password>"] <target>
>```
<!-- }}} -->

<!-- }}} -->

<!-- Additional Scripts {{{-->
### Additional Scripts

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

<!-- }}} -->

___
<!-- }}} -->

<!-- CrackMapExec {{{-->
## CrackMapExec

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
— Enumerate SMB services

> [!warning]
>
> **DEPRECATED** to [NetExe](https://github.com/Pennyw0rth/NetExec)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> crackmapexec smb <target>
> ```
>
> ```sh
> crackmapexec smb <target> --pass-pol -u "" -p ""
> ```
>
> ```sh
> crackmapexec smb <target> --pass-pol -u "guest" -p ""
> ```
>
> ```sh
> SMB         10.129.14.128   445    DEVSMB           [*] Windows 6.1 Build 0 (name:DEVSMB) (domain:) (signing:False) (SMBv1:False)
> SMB         10.129.14.128   445    DEVSMB           [+] \: 
> SMB         10.129.14.128   445    DEVSMB           [+] Enumerated shares
> SMB         10.129.14.128   445    DEVSMB           Share           Permissions     Remark
> SMB         10.129.14.128   445    DEVSMB           -----           -----------     ------
> SMB         10.129.14.128   445    DEVSMB           print$                          Printer Drivers
> SMB         10.129.14.128   445    DEVSMB           home                            INFREIGHT Samba
> SMB         10.129.14.128   445    DEVSMB           dev                             DEVenv
> SMB         10.129.14.128   445    DEVSMB           notes           READ,WRITE      CheckIT
> SMB         10.129.14.128   445    DEVSMB           IPC$                            IPC Service (DEVSM)
> ```
<!-- }}} -->

___
<!-- }}} -->
