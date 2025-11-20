---
id: WPScan
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Tools/WPScan
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# WPScan

[WPScan](https://github.com/wpscanteam/wpscan)
— WordPress security scanner

___

<!-- Usage {{{-->
## Usage

Simple scan (*no exploitation*)

```sh
wpscan --url <target>
```

Enumerate users

```sh
wpscan --url <target> --enumerate u
```

Enumerate a range of users

```sh
wpscan --url <target> --enumerate u1-100
```

Bruteforce a user

```sh
wpscan --url <target> --username <username> --passwords "<wordlist.txt>"
```

Enumerate and bruteforce users

```sh
wpscan --url <target> --enumerate u --passwords "<wordlist.txt>"
```
<!-- }}} -->
