---
id: Enumeration
aliases: []
tags:
  - Networking/Services/IPMI/Enumeration
---

# Enumeration

## Checklist

- [ ] [[Enumeration#Nmap|Nmap]]
    - [ ] [[Enumeration#Network Scan|Network Scan]]
    - [ ] [[Enumeration#Service Enumeration|Service Enumeration]]
- [ ] [[Enumeration#Metasploit|Metasploit]]
    - [ ] [[Enumeration#Version Scan|Version Scan]]

___

<!-- Nmap {{{-->
## Nmap

<!-- Network Scan {{{-->
### Network Scan

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

<!-- }}} -->

<!-- Service Enumeration {{{-->
### Service Enumeration

Footprint the service with the `ipmi-version`
[[Nmap Scripting Engine|NSE]] script

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

<!-- }}} -->

___

<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

Discover host information through IPMI Channel Auth probes
([ipmi_version](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/))

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

<!-- }}} -->

___

<!-- }}} -->
