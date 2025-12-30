---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SNMP/Enumeration
links: "[[Services]]"
---

# Enumeration

The objective of the enumeration is to reveal
[[#Community Strings]] and [[#OID|Object Identifiers]]

Examination of process parameters might reveal

- credentials
- routing information
- services bound to additional interfaces when passed on the command line

___

<!-- Service {{{-->
## Service

Service detection and enumeration

[[Nmap]] — Identify SNMP service

```sh
nmap -sU $target -p 161 --open -oA snmp-identify
```

[[Nmap]] — Extract system information from an SNMP service
(*[snmp-sysdescr](https://nmap.org/nsedoc/scripts/snmp-sysdescr.html)*)

```sh
nmap -sU -sV $target -p 161 --script snmp-sysdescr -oA snmp-script-sysdescr
```

[[Nmap]] — Enumerate network interfaces
(*[snmp-interfaces](https://nmap.org/nsedoc/scripts/snmp-interfaces.html)*)

```sh
nmap -sU -sV $target -p 161 --script snmp-interfaces -oA snmp-script-interfaces
```

[[Nmap]] — Enumerate listening TCP/UDP ports
(*[snmp-netstat](https://nmap.org/nsedoc/scripts/snmp-netstat.html)*)

```sh
nmap -sU -sV $target -p 161 --script snmp-netstat -oA snmp-script-netstat
```

[[Nmap]] — Enumerate running processes
(*[snmp-processes](https://nmap.org/nsedoc/scripts/snmp-processes.html)*)

```sh
nmap -sU -sV $target -p 161 --script snmp-processes -oA snmp-script-processes
```

<!-- Banner Grabbing {{{-->
### Banner Grabbing

[[Nmap]] — Grab service banner (*[snmp-info](https://nmap.org/nsedoc/scripts/snmp-info.html)*)

```sh
nmap -sU $target -p 161 --script snmp-info -oA snmp-script-banner-grabbing
```

<!-- }}} -->

<!-- Windows {{{-->
### Windows

[[Metasploit]] — Enumerate SNMP (*Windows only*)

SNMP Enumeration Module
(*[snmp_enum](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_enum/)*)

```sh
use auxiliary/scanner/snmp/snmp_enum
```

<!-- Example {{{-->
> [!example]-
>
> Enumeration of any devices with SNMP protocol support.
> It supports hardware, software, and network information.
> The default community string used is `public`.
>
> ```sh
> msfconsole
> ```
> ```sh
> msf > use auxiliary/scanner/snmp/snmp_enum
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enum) > set RHOSTS target.com
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enum) > set COMMUNITY <community_string> # Defaults to public
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enum) > run
> ```
<!-- }}} -->

SNMP Windows Username Enumeration
(*[snmp_enumusers](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_enumusers/)*)

```sh
use auxiliary/scanner/snmp/snmp_enumusers
```

<!-- Example {{{-->
> [!example]-
>
> Use LanManager/psProcessUsername OID values
> to enumerate local user accounts on a Windows/Solaris system via SNMP
>
> ```sh
> msf > use auxiliary/scanner/snmp/snmp_enumusers # If enumerating users on Windows via SNMP
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enumusers) > set RHOSTS $target
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enumusers) > run
> ```
<!-- }}} -->

SNMP Windows SMB Share Enumeration
(*[snmp_enumshares](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_enumshares/)*)

```sh
use auxiliary/scanner/snmp/snmp_enumshares
```

<!-- Example {{{-->
> [!example]-
>
> Use LanManager OID values to enumerate SMB shares on a Windows system via SNMP
>
> ```sh
> msf > use auxiliary/scanner/snmp/snmp_enumshares # If enumerating shares on Windows via SNMP
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enumshares) > set RHOSTS target.com
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_enumshares) > run
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Community Strings {{{-->
## Community Strings

[[Networking/Services/SNMP/General#Community Strings|Community Strings]]
should be discovered via dictionary attack

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [OneSixtyOne - dict.txt](https://github.com/trailofbits/onesixtyone/blob/master/dict.txt)`
>
> - [[SecLists]]
>
> ```sh
> /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt
> ```
>
> - [[Metasploit]]
>
> ```sh
> /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
> ```
<!-- }}} -->

[onesixtyone](https://github.com/trailofbits/onesixtyone) —
Identify [[Networking/Services/SNMP/General#Community Strings|community strings]]

```sh
onesixtyone -c <wordlist.txt> $target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 10.129.14.128
> ```
> ```sh
> Scanning 1 hosts, 3220 communities
> 10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
> ```
<!-- }}} -->

[[Metasploit]] — SNMP Community Login Scanner
(*[snmp_login](https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_login/)*)

```sh
use auxiliary/scanner/snmp/snmp_login
```

<!-- Example {{{-->
> [!example]-
>
> Log in to SNMP devices using common
> [[Networking/Services/SNMP/General#Community Strings|community strings]]
>
> 1. [[Metasploit#Search Exploit|Search Exploit]]
>
> ```sh
> msf > search snmp
> ```
>
> 2. [[Metasploit#Select Exploit|Select Exploit]]
>
> ```sh
> msf > use auxiliary/scanner/snmp/snmp_login
> ```
>
> 3. [[Metasploit#Show Options|Show Options]]
>
> 4. [[Metasploit#Set Options|Set Options]]
>
> ```sh
> msf auxiliary(scanner/snmp/snmp_login) > set RHOSTS $target
> ```
> ```sh
> msf auxiliary(scanner/snmp/snmp_login) > set PASS_FILE </path/to/community_wordlist.txt>
> ```
>
> 5. [[Metasploit#Run Exploit|Run Exploit]]
>
> ```sh
> msf auxiliary(scanner/snmp/snmp_login) > run
> ```
<!-- }}} -->

[[Nmap]] — Find an SNMP community string by brute force guessing
(*[snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html)*)

```sh
nmap -sU $target -p 161 --script snmp-brute [--script-args snmp-brute.communitiesdb=<wordlist.txt>]
```

[[Hydra]] — Brute force

```sh
hydra -P <wordlist.txt> $target snmp
```

[snmpwalk](https://linux.die.net/man/1/snmpwalk) —
SNMP installation often retain default or weak community strings

<!-- Example {{{-->
> [!example]-
>
> ```sh
> snmpwalk -c public -v1 $target
> ```
>
> ```sh
> snmpwalk -c private -v1 $target
> ```
>
> ```sh
> snmpwalk -c public -v2c $target
> ```
>
> ```sh
> snmpwalk -c private -v2c $target
> ```
>
> ```sh
> snmpwalk -c admin -v2c $target
> ```
>
> ```sh
> snmpwalk -c manager -v2c $target
> ```
>
> ```sh
> snmpwalk -c community -v2c $target
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- OID {{{-->
## OID

Extract comprehensive information from SNMP-enabled devices
using specific Object Identifiers
(*[[Networking/Services/SNMP/General#OID|OIDs]]*)

<!-- Warning {{{-->
> [!warning]
>
> A valid [[Networking/Services/SNMP/General#Community Strings|Community String]] must be known
> (*e.g., `public`, `private`, etc.*)
<!-- }}} -->

<!-- Snmpget {{{-->
### Snmpget

[snmpget](https://linux.die.net/man/1/snmpget) —
Communicates with a network entity using `SNMP GET` requests

```sh
snmpget [COMMON OPTIONS] [-Cf] OID [OID]... 
```

System description (*`sysDescr`*)

```sh
snmpget -v1 -c public $target .1.3.6.1.2.1.1.1.0
```

```sh
snmpget -v2c -c public $target sysDescr.0
```
<!-- }}} -->

<!-- Snmpwalk {{{-->
### Snmpwalk

[snmpwalk](https://linux.die.net/man/1/snmpwalk) —
Retrieve a subtree of management values using `SNMP GETNEXT` requests

```sh
snmpwalk [APPLICATION OPTIONS] [COMMON OPTIONS] [OID] 
```

<!-- Example {{{-->
> [!example]-
>
> Once the community string is known and the SNMP service (*`v1` or `v2c`*)
> does not require authentication, internal system information can be queried
>
> ```sh
> snmpwalk -v 2c -c private 10.129.42.253
> ```
>
> > [!info]
> >
> > - `-v2c`: Query `SNMPv2c`
> > - `-c private`: Community string `private` — the default write string on
> >   some devices
>
> In case of a misconfiguration, similar to the following result is shown.
>
> > [!example]-
> >
> > ```sh
> > iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
> > iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
> > iso.3.6.1.2.1.1.3.0 = Timeticks: (5134) 0:00:51.34
> > iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
> > iso.3.6.1.2.1.1.5.0 = STRING: "htb"
> > iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
> > iso.3.6.1.2.1.1.7.0 = INTEGER: 72
> > iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
> > iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
> > iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
> > iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
> > iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
> > iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
> > iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.4
> > iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.50
> > iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
> > iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
> > iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
> > iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
> > iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
> > iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
> > iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
> > iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
> > iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing IP and ICMP implementations"
> > iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing UDP implementations"
> > iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
> > iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
> > iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (0) 0:00:00.00
> > iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3676678) 10:12:46.78
> > iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 09 14 0E 2B 2D 00 2B 02 00 
> > iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
> > iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-5.11.0-34-generic root=UUID=9a6a5c52-f92a-42ea-8ddf-940d7e0f4223 ro quiet splash"
> > iso.3.6.1.2.1.25.1.5.0 = Gauge32: 3
> > iso.3.6.1.2.1.25.1.6.0 = Gauge32: 411
> > iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
> > iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
> >
> > ...SNIP...
> >
> > iso.3.6.1.2.1.25.6.3.1.2.1232 = STRING: "printer-driver-sag-gdi_0.1-7_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1233 = STRING: "printer-driver-splix_2.0.0+svn315-7fakesync1build1_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1234 = STRING: "procps_2:3.3.16-1ubuntu2.3_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1235 = STRING: "proftpd-basic_1.3.6c-2_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1236 = STRING: "proftpd-doc_1.3.6c-2_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1237 = STRING: "psmisc_23.3-1_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1238 = STRING: "publicsuffix_20200303.0012-1_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1239 = STRING: "pulseaudio_1:13.99.1-1ubuntu3.12_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1240 = STRING: "pulseaudio-module-bluetooth_1:13.99.1-1ubuntu3.12_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1241 = STRING: "pulseaudio-utils_1:13.99.1-1ubuntu3.12_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1242 = STRING: "python-apt-common_2.0.0ubuntu0.20.04.6_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
> > iso.3.6.1.2.1.25.6.3.1.2.1244 = STRING: "python3-acme_1.1.0-1_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1245 = STRING: "python3-apport_2.20.11-0ubuntu27.21_all"
> > iso.3.6.1.2.1.25.6.3.1.2.1246 = STRING: "python3-apt_2.0.0ubuntu0.20.04.6_amd64" 
> >
> > ...SNIP...
> > ```
>
> The SNMP request went out but no UDP response came back
> on the target on (*port `UDP/161`*)
>
> ```
> Timeout: No Response from 10.129.42.253
> ```
<!-- }}} -->

Connect and walk the entire [[Networking/Services/SNMP/General#MIB|MIB]] tree (*SNMPv1/v2c*)

```sh
snmpwalk -v 1 -c <community_string> $target | tee SNMPWALK.txt
```

```sh
snmpwalk -v 2c -c <community_string> $target | tee SNMPWALK.txt
```

#### System

Hostname

```sh
snmpwalk -v <version> -c public $target 1.3.6.1.2.1.1.5.0
```

System Description

```sh
snmpget -v <version> -c public $target .1.3.6.1.2.1.1.1.0
```

System information

```sh
snmpwalk -v <version> -c public $target system
```

System Uptime

```sh
snmpwalk -v <version> -c public $target hrSystemUptime
```

System CPU load (*Net-SNMP*)

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.4.1.2021.11
```

Usernames and storage descriptions (*especially on Windows systems*)

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.4.1.77.1.2.25
```

```sh
snmpwalk -v <version> -c public $target hrStorageTable
```

<!-- Example {{{-->
> [!example]-
>
> Enumerating SNMP info — getting hostname
>
>```sh
>snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
>```
> > [!info]-
> >
> > - `-v 2c`: Query `SNMPv2c`
> > - `-c public`: Community string `public` — the default read-only "password"
> >   on many misconfigured devices
> > - `1.3.6.1.2.1.1.5.0`: Specific `OID` being queried — it corresponds to
> > `sysName.0`, the system's configured name
>
>```sh
>iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
>```
>
> > [!info]-
> >
> > - The target device responded
> > - Allowed access to the `public` community string
> > - Revealed its system name: `gs-svcscan`
<!-- }}} -->

#### Network

Network information (*Routing tables*)

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.4.21.1.1
```

```sh
snmpwalk -v <version> -c public $target ipAddrTable
```

Network information (*ARP cache*)

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.4.22.1.3
```

Network interface configurations

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.1.1.0
```

```sh
snmpwalk -v <version> -c public $target interfaces
```

Network interface descriptions

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.2.2.1.2
```

Network interface IP addresses

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.4.20.1.1
```

Network Interface Status

```sh
snmpwalk -v2c -c public target.com .1.3.6.1.2.1.2.2.1.8
```

#### Services

Running services and processes

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.25.4.2.1.2
```

```sh
snmpwalk -v <version> -c public $target hrSWRunTAble
```

Software versions

```sh
snmpwalk -v <version> -c public $target .1.3.6.1.2.1.25.6.3.1.2
```

<!-- }}} -->

<!-- Braa {{{-->
### Braa

[braa](https://github.com/mteg/braa) —
Brute force [[Networking/Services/SNMP/General#OID|OIDs]] and information enumeration

Installation

```sh
sudo apt install braa
```

Syntax

```sh
braa <community_string>@$target:.1.3.6.*
```

<!-- Example {{{ -->
> [!example]-
>
> ```sh
> braa public@10.129.14.128:.1.3.6.*
> ```
>
> > [!info]-
> >
> > - `public`: `public` community string
> > - `.1.3.6.*`: Query anything under this SNMP tree
>
> ```sh
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.3.0:548
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.5.0:htb
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.6.0:US
> 10.129.14.128:20ms:.1.3.6.1.2.1.1.7.0:78
> ...SNIP...
> ```
>
> > [!info]-
> >
> > - `braa` returned with the `OID` values and their meanings
> > - Discovered agent: `Net-SNMP` on `Linux (Ubuntu)`
> > - Discovered contact: `mrb3n@inlanefreight.htb`, that may reveal potential
> >   credentials
> >
> > Practical next moves:
> >
> > - Full `snmpwalk` of more `OID`s (e.g., `1.3.6.1.2.1` (system, interfaces))
> > - Check for read-write community (e.g., `private`, `write`, etc.) as a
> >   writeable community may allow remote code execution
> > - Correlate the username `mrb3n` across other services
>
<!-- }}} -->

<!-- }}} -->
___

<!-- }}} -->
