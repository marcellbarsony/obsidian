---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SNMP/Enumeration
links: "[[Services]]"
---

<!-- Enumeration {{{-->
# Enumeration

The objective of the enumeration is to reveal
[[#Community Strings]] and [[#OID|Object Identifiers)]]

Examination of process parameters might reveal

- credentials
- routing information
- services bound to additional interfaces when passed on the command line


___

<!-- }}} -->

<!-- Checklist {{{-->
## Checklist

- [ ] [[#Nmap]]
    - [ ] [[#Banner Grabbing]]
- [ ] [[#sysDescr]]
    - [ ] [[#snmpget]]
- [ ] [[#Community Strings]]
    - [ ] [[#OneSixtyOne]]
    - [ ] [[#Metasploit]]
    - [ ] [[#SNMPwalk]]
- [ ] [[#OID]]
    - [ ] [[#Braa]]
    - [ ] [[#OID#SNMPwalk|SNMPwalk]]

___

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Service detection

```sh
nmap -sU -p 161 --open <target> -oA snmp-identify
```

### Banner Grabbing

Grab service banner

```sh
nmap -sU -p 161 --script snmp-info <target> -oA snmp-banner-grabbing
```

___

<!-- }}} -->

<!-- sysDescr {{{-->
## sysDescr

Connect to SNMP services to gather version and system information

<!-- snmpget {{{-->
### snmpget

Retrieve system description (`sysDescr`) with
[snmpget](https://linux.die.net/man/1/snmpget)

```sh
snmpget -v1 -c public <target> .1.3.6.1.2.1.1.1.0
```

```sh
snmpget -v2c -c public <target> sysDescr.0
```

<!-- }}} -->

<!-- snmpwalk {{{-->
### snmpwalk

Network topology (routing tables, ARP caches)

```sh
snmpwalk -c public -v2c <target> .1.3.6.1.2.1.4.22.1.3
```

Device configurations

```sh
snmpwalk -c public -v2c <target> .1.3.6.1.2.1.1.1.0
```

Usernames (especially on Windows systems)

```sh
snmpwalk -c public -v2c <target> .1.3.6.1.4.1.77.1.2.25
```

Running services and processes

```sh
snmpwalk -c public -v2c <target> .1.3.6.1.2.1.25.4.2.1.2
```

Software versions

```sh
snmpwalk -c public -v2c <target> .1.3.6.1.2.1.25.6.3.1.2
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Community Strings {{{-->
## Community Strings

[[General#Community Strings|Community Strings]]
should be discovered via dictionary attack

<!-- Tip {{{ -->
> [!tip]
>
> **SNMP Community Strings** dictionaries
>
> - [OneSixtyOne - dict.txt](https://github.com/trailofbits/onesixtyone/blob/master/dict.txt)`
> - [SecLists - SNMP Community Strings](https://github.com/danielmiessler/SecLists/tree/master/Discovery/SNMP)
> - Metasploit wordlist - `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`
<!-- }}} -->

<!-- OneSixtyOne {{{-->
### OneSixtyOne

[onesixtyone](https://github.com/trailofbits/onesixtyone)
is used to identify **community strings**


```sh
onesixtyone -c <wordlist.txt> <target>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
> ```
> ```sh
> Scanning 1 hosts, 3220 communities
> 10.129.14.128 [public] Linux htb 5.11.0-37-generic #41~20.04.2-Ubuntu SMP Fri Sep 24 09:06:38 UTC 2021 x86_64
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Metasploit {{{-->
### Metasploit

Identify [[General#Community Strings|community strings]] with [[Metasploit]]

<!-- Example {{{-->
> [!example]-
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
> msf auxiliary(scanner/snmp/snmp_login) > set RHOSTS <target_ip>
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

<!-- }}} -->

<!-- Nmap {{{-->
### Nmap

Brute force with [[Nmap]]'s [snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html)
script

```sh
nmap -sU -p 161 --script snmp-brute [--script-args snmp-brute.communitiesdb=<wordlist.txt> ] <target>
```

<!-- }}} -->

<!-- Hydra {{{-->
### Hydra

Brute force with [[Hydra]]

```sh
hydra -P <wordlist.txt> <target> snmp
```

<!-- }}} -->

<!-- SNMPwalk {{{-->
### SNMPwalk

SNMP installation often retain default or weak community strings

<!-- Example {{{-->
> [!example]-
>
> ```sh
> snmpwalk -c public -v1 <target>
> ```
>
> ```sh
> snmpwalk -c private -v1 <target>
> ```
>
> ```sh
> snmpwalk -c public -v2c <target>
> ```
>
> ```sh
> snmpwalk -c private -v2c <target>
> ```
>
> ```sh
> snmpwalk -c admin -v2c <target>
> ```
>
> ```sh
> snmpwalk -c manager -v2c <target>
> ```
>
> ```sh
> snmpwalk -c community -v2c <target>
> ```
<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- OID {{{-->
## OID

Enumerate [[General#OID|Object Identifier]]s

<!-- SNMPwalk {{{-->
### SNMPwalk

[snmpwalk](https://linux.die.net/man/1/snmpwalk)
can be used to **query [[General#OID|OID]]s** with their information

<!-- Important {{{-->
> [!important]
>
> A valid community string must be known (e.g., `public`, `private`, etc.)
<!-- }}} -->

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

<!-- Example 2 {{{-->
> [!example]- Example 2
>
> ```sh
> snmpwalk -v 2c -c private  10.129.42.253
> ```
>
> > [!info]-
> >
> > - `-v2c`: Query `SNMPv2c`
> > - `-c private`: Community string `private` — the default write string on
> >   some devices
>
> ```
> Timeout: No Response from 10.129.42.253
> ```
>
> > [!info]-
> >
> > The SNMP request went out but no UDP response came back on the target on
> > port 161
<!-- }}} -->

<!-- Example 3 {{{-->
> [!example]- Example 3
>
> In case of a misconfiguration, similar to the following result is shown.
>
> Once the community string is known and the SNMP service (`v1` or `v2c`) does
> not require authentication, internal system information can be queried
>
> ```sh
> snmpwalk -v 2c -c public 10.129.14.128
> ```
>
> > [!info]-
> >
> > - `-v2c`: Query `SNMPv2c`
> > - `-c public`: Community string `public` — the default read-only "password"
> >   on many misconfigured devices
>
> ```sh
> iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
> iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
> iso.3.6.1.2.1.1.3.0 = Timeticks: (5134) 0:00:51.34
> iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
> iso.3.6.1.2.1.1.5.0 = STRING: "htb"
> iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
> iso.3.6.1.2.1.1.7.0 = INTEGER: 72
> iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
> iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
> iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
> iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
> iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
> iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
> iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.4
> iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.50
> iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
> iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
> iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
> iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
> iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
> iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
> iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
> iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
> iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing IP and ICMP implementations"
> iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing UDP implementations"
> iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
> iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
> iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (0) 0:00:00.00
> iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3676678) 10:12:46.78
> iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 09 14 0E 2B 2D 00 2B 02 00 
> iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
> iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-5.11.0-34-generic root=UUID=9a6a5c52-f92a-42ea-8ddf-940d7e0f4223 ro quiet splash"
> iso.3.6.1.2.1.25.1.5.0 = Gauge32: 3
> iso.3.6.1.2.1.25.1.6.0 = Gauge32: 411
> iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
> iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
> 
> ...SNIP...
> 
> iso.3.6.1.2.1.25.6.3.1.2.1232 = STRING: "printer-driver-sag-gdi_0.1-7_all"
> iso.3.6.1.2.1.25.6.3.1.2.1233 = STRING: "printer-driver-splix_2.0.0+svn315-7fakesync1build1_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1234 = STRING: "procps_2:3.3.16-1ubuntu2.3_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1235 = STRING: "proftpd-basic_1.3.6c-2_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1236 = STRING: "proftpd-doc_1.3.6c-2_all"
> iso.3.6.1.2.1.25.6.3.1.2.1237 = STRING: "psmisc_23.3-1_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1238 = STRING: "publicsuffix_20200303.0012-1_all"
> iso.3.6.1.2.1.25.6.3.1.2.1239 = STRING: "pulseaudio_1:13.99.1-1ubuntu3.12_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1240 = STRING: "pulseaudio-module-bluetooth_1:13.99.1-1ubuntu3.12_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1241 = STRING: "pulseaudio-utils_1:13.99.1-1ubuntu3.12_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1242 = STRING: "python-apt-common_2.0.0ubuntu0.20.04.6_all"
> iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
> iso.3.6.1.2.1.25.6.3.1.2.1244 = STRING: "python3-acme_1.1.0-1_all"
> iso.3.6.1.2.1.25.6.3.1.2.1245 = STRING: "python3-apport_2.20.11-0ubuntu27.21_all"
> iso.3.6.1.2.1.25.6.3.1.2.1246 = STRING: "python3-apt_2.0.0ubuntu0.20.04.6_amd64" 
> 
> ...SNIP...
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Braa {{{-->
### Braa

[braa](https://github.com/mteg/braa) is used for **brute forincg
[[General#OID|OID]]s** and information enumeration

> [!important]
>
> A valid community string must be known (e.g., `public`, `private`, etc.)

<!-- Installation {{{-->
#### Installation

```sh
sudo apt install braa
```

<!-- }}} -->

<!-- Syntax {{{-->
#### Syntax

```sh
braa <community string>@<IP>:.1.3.6.*
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

<!-- }}} -->

___

<!-- }}} -->
