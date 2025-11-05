---
id: Enumeration
aliases: []
tags:
  - Networking/Services/IPMI/Enumeration
---

# Enumeration

___

<!-- Network Scan {{{-->
## Network Scan

Scan the network for port TCP/UDP `623`

```sh
nmap -n -p 623 <target>/<cidr> -oA ipmi-basic
```

```sh
nmap -n -sU -p 623 <target>/<cidr> -oA ipmi-basic-udp
```

<!-- Info {{{-->
> [!info]-
>
> - `-n`: Desable DNS resolution
> - `-p 623`: Scan port `623`
> - `-sU`: Scan UDP port
<!-- }}} -->

___
<!-- }}} -->

<!-- Service Enumeration {{{-->
### Service Enumeration

[[Nmap]] — Footprint the service
(*[ipmi-version](https://nmap.org/nsedoc/scripts/ipmi-version.html)*)

```sh
sudo nmap -sU -p 623 --script ipmi-version <target_domain> -oA ipmi-version
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
> ```
> ```sh
> Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-04 21:48 GMT
> Nmap scan report for ilo.inlanfreight.local (172.16.2.2)
> Host is up (0.00064s latency).
>
> PORT    STATE SERVICE
> 623/udp open  asf-rmcp
> | ipmi-version:
> |   Version:
> |     IPMI-2.0
> |   UserAuth:
> |   PassAuth: auth_user, non_null_user
> |_  Level: 2.0
> MAC Address: 14:03:DC:674:18:6A (Hewlett Packard Enterprise)
>
> Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
> ```
>
> - [[General|IPMI]] version 2.0 is listening on port `623`/UDP
>
<!-- }}} -->

[[Metasploit]] —
Discover host information through IPMI Channel Auth probes
(*[ipmi_version](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/)*)

```sh
msf6 > use auxiliary/scanner/ipmi/ipmi_version
```

<!-- Example {{{-->
> [!example]-
>
> 1. [[Metasploit#Select Exploit|Select scanner]]
>
> ```sh
> msf6 > use auxiliary/scanner/ipmi/ipmi_version
> ```
>
> 2. [[Metasploit#Set Options|Select options]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
> ```
>
> 3. [[Metasploit#Show Options|Show options]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_version) > show options
> ```
>
> ```sh
> Module options (auxiliary/scanner/ipmi/ipmi_version):
>
>    Name       Current Setting  Required  Description
>    ----       ---------------  --------  -----------
>    BATCHSIZE  256              yes       The number of hosts to probe in each set
>    RHOSTS     10.129.42.195    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
>    RPORT      623              yes       The target port (UDP)
>    THREADS    10               yes       The number of concurrent threads
> ```
>
> 4. [[Metasploit#Run Exploit|Run the scan]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_version) > run
> ```
>
> ```sh
> [*] Sending IPMI requests to 10.129.42.195->10.129.42.195 (1 hosts)
> [+] 10.129.42.195:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
> [*] Scanned 1 of 1 hosts (100% complete)
> [*] Auxiliary module execution completed
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Cipher Zero {{{-->
### Cipher Zero

[[Nmap]] — IPMI 2.0 Cipher Zero Authentication Bypass
(*[ipmi-cipher-zero](https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html)*)

```sh
nmap -sU --script ipmi-cipher-zero -p 623 <target> -oA ipmi-script-cipher-zero
```

[[Metasploit]] — IPMI 2.0 Cipher Zero Authentication Bypass Scanner
(*[ipmi_cipher_zero](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_cipher_zero/)*)

```sh
use auxiliary/scanner/ipmi/ipmi_cipher_zero
```

<!-- Example {{{-->
> [!example]-
>
> Identifies IPMI 2.0-compatible systems that are vulnerable
> to an authentication bypass vulnerability through the use of cipher zero
>
> ```sh
> msf > use auxiliary/scanner/ipmi/ipmi_cipher_zero
> msf auxiliary(ipmi_cipher_zero) > show actions
>     ...actions...
> msf auxiliary(ipmi_cipher_zero) > set ACTION < action-name >
> msf auxiliary(ipmi_cipher_zero) > show options
>     ...show and set options...
> msf auxiliary(ipmi_cipher_zero) > run
> ```
<!-- }}} -->

<!-- }}} -->
