---
id: Enumeration
aliases: []
tags:
  - Networking/Services/RDP/Enumeration
links:
  [[Services]]
---

# Enumeration

___

<!-- Service Detection {{{-->
## Service Detection

Detect RDP services and identify capabilities with [[Nmap]]

```sh
nmap -p 3389 <target> -oA rdp-identify
```

___

<!-- }}} -->

<!-- Version and Configuration Check {{{-->
## Version and Configuration Check

Extract RDP version and security configuration information.

Check Windows version through RDP

```sh
nmap -p 3389 --script rdp-ntlm-info <target> -oA rdp-script-ntlm-info
```

> [!tip]-
>
> - Check if [[General#Network Level Authentication|NLA]] is enabled

Check security layer

```sh
nmap -p 3389 --script rdp-enum-encryption <target> -oA rdp-script-enum-encryption
```

> [!info]-
>
> The output shows:
>
> - RDP Protocol version
> - Security layer (RDP/TLS/CredSSP)
> - Encryption level

Run all scripts (*including [rdp-vuln-ms12-020](https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html)*)

```sh
nmap -sC -sV <target> -p 3389 --script rdp* -oA rdp-script-all
```

```sh
nmap -sC -sV <target> -p 3389 --packet-trace --disable-ap-ping -n -oA rdp-script-trace
```
___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Connect to RDP services to gather version and security information

Using [[Nmap]]

```sh
nmap -p 3389 -sV <target>
```

Using [rdp-sec-check](https://github.com/CiscoCXSecurity/rdp-sec-check)

```sh
python rdp-sec-check.py <target>
```

___

<!-- }}} -->

<!-- Certificate {{{-->
## Certificate

Check RDP certificate with [openssl](https://en.wikipedia.org/wiki/OpenSSL)

```sh
openssl s_client -connect <target>:3389 < /dev/null 2>&1 | openssl x509 -noout -text
```

___

<!-- }}} -->

<!-- RDP Security Check {{{-->
## RDP Security Check

Perl script developed by [Cisco CX Security Labs](https://github.com/CiscoCXSecurity)
to enumerate security settings of an RDP Service

Clone the [repository](https://github.com/CiscoCXSecurity/rdp-sec-check)

```sh
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
```

Launch the script against the target

```sh
./rdp-sec-check.pl <target>
```

___

<!-- }}} -->

<!-- User Enumeration {{{-->
## User Enumeration

RDP allows username enumeration

> [!info]-
>
> Through RDP login attempts RDP returns different errors for
>
> - Valid user, wrong password
> - Invalid user

> [!tip]-
>
> Check for common usernames
> (*e.g., `Administrator`, `admin`, `user`, `guest`, etc.*)

Using rdp_check (*C# tool*)

```sh
rdp_check.exe <target> <usernames.txt>
```

Using [rdp_check.py](https://github.com/fortra/impacket/blob/master/examples/rdp_check.py)

```sh
rdp_check.py [-hashes LMHASH:NTHASH] <target>
```

Using [crowbar](https://github.com/galkan/crowbar)

```sh
crowbar -b rdp -s <target>/<cidr> -u <usernames.txt> -C <passwords.txt>
```

___

<!-- }}} -->

<!-- Session Enumeration {{{-->
## Session Enumeration

Enumerate active RDP sessions
to identify logged-in users and their session states

> [!warning]
>
> Access required

List active sessions

```sh
qwinsta /server:<target>
```

Query user sessions

```sh
query user /server:<target>
```

Session information

```sh
quser /server:<target>
```

___

<!-- }}} -->
