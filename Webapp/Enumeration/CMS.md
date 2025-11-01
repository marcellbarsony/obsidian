---
id: CMS
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/CMS
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# CMS

<!-- Enumeration {{{-->
## Enumeration

Identify technologies on websites

<!-- Online Tools {{{-->
### Online Tools

- [Wappalyzer](https://www.wappalyzer.com/)

- [Whatcms](https://whatcms.org/)

<!-- }}} -->

<!-- WordPress {{{-->
### WordPress

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
wpscan --url <target> --username $username --passwords "/path/to/wordlist.txt"
```

Enumerate and bruteforce users

```sh
wpscan --url <target> --enumerate u --passwords "/path/to/wordlist.txt"
```

<!-- }}} -->

___
<!-- }}} -->
