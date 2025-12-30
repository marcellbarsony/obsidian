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

<!-- Service {{{-->
## Service

[[Nmap]] — Detect RDP services and identify capabilities

```sh
nmap $target -p 3389 -oA rdp-identify
```

<!-- Banner Grabbing {{{-->
### Banner Grabbing

Grab to RDP service banner
(*version and security information*)

[[Netcat]]

```sh
ncat -nv $target 3389
```

[[Nmap]]

```sh
nmap -sV $target -p 3389 -oA rdp-default-scan
```

[[#RDP Security Check]]

```sh
python rdp-sec-check.py $target
```

[[Telnet/General|Telnet]]

```sh
telnet $target 3389
```

<!-- }}} -->

<!-- Version and Configuration {{{-->
### Version and Configuration

Extract RDP version and security configuration information

[[Nmap]] — Check Windows version through RDP

```sh
nmap $target -p 3389 --script rdp-ntlm-info -oA rdp-script-ntlm-info
```

<!-- Tip {{{-->
> [!tip]-
>
> - Check if [[Networking/Services/RDP/General#Network Level Authentication|NLA]] is enabled
<!-- }}} -->

[[Nmap]] — Check security layer

```sh
nmap $target -p 3389 --script rdp-enum-encryption -oA rdp-script-enum-encryption
```

<!-- Info {{{-->
> [!info]-
>
> The output shows
>
> - RDP Protocol version
> - Security layer (RDP/TLS/CredSSP)
> - Encryption level
<!-- }}} -->

[[Nmap]] — Run all scripts
(*including [rdp-vuln-ms12-020](https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html)*)

```sh
nmap -sC -sV $target -p 3389 --script rdp* -oA rdp-script-all
```

```sh
nmap -sC -sV $target -p 3389 --packet-trace --disable-ap-ping -n -oA rdp-script-trace
```

<!-- }}} -->

<!-- Certificate {{{-->
### Certificate

[openssl](https://en.wikipedia.org/wiki/OpenSSL) —
Check RDP certificate

```sh
openssl s_client -connect $target:3389 < /dev/null 2>&1 | openssl x509 -noout -text
```

<!-- }}} -->

<!-- RDP Security Check {{{-->
### RDP Security Check

Perl script developed by [Cisco CX Security Labs](https://github.com/CiscoCXSecurity)
to enumerate security settings of an RDP Service

1. Clone the [repository](https://github.com/CiscoCXSecurity/rdp-sec-check)

```sh
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
```

2. Launch the script against the target

```sh
./rdp-sec-check.pl $target
```

<!-- }}} -->

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

[[Impacket]] - [rdp_check.py](https://github.com/fortra/impacket/blob/master/examples/rdp_check.py)

```sh
impacket-rdp_check [-hashes LMHASH:NTHASH] $target
```

[crowbar](https://github.com/galkan/crowbar)

```sh
crowbar -b rdp -s $target/<cidr> -u <usernames.txt> -C <passwords.txt>
```

Using rdp_check (*C# tool*)

```sh
rdp_check.exe $target <usernames.txt>
```

___

<!-- }}} -->

<!-- Session Enumeration {{{-->
## Session Enumeration

Enumerate active RDP sessions
to identify logged-in users and their session states

<!-- Warning {{{-->
> [!warning]
>
> Access required
<!-- }}} -->

List active sessions

```sh
qwinsta /server:$target
```

Query user sessions

```sh
query user /server:$target
```

Session information

```sh
quser /server:$target
```

___
<!-- }}} -->
