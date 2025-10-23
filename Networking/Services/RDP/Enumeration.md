---
id: Enumeration
aliases: []
tags:
  - Networking/Services/RDP/Enumeration
links:
  [[Services]]
---

# Enumeration

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

Check security layer

```sh
nmap -p 3389 --script rdp-enum-encryption <target> -oA rdb-script-enum-encryption
```

> [!info]-
>
> The output shows:
>
> - RDP Protocol version
> - Security layer (RDP/TLS/CredSSP)
> - Encryption level

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
