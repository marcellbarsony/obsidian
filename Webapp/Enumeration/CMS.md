---
id: CMS
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/CMS
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# CMS

## Enumeration

Identify technologies on websites

- [Wappalyzer](https://www.wappalyzer.com/)

- [Whatcms](https://whatcms.org/)

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
