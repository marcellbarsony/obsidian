---
id: Enumeration Tools
aliases:
  - WinPEAS
tags:
  - Microsoft/Windows/Privesc/Tools
links: PrivescWin
---

# Enumeration Tools

- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html?highlight=winpeas#best-tool-to-look-for-windows-local-privilege-escalation-vectors----winpeas)

___

<!-- Enumeration Scripts {{{-->
## Enumeration Scripts

> [!warning]
> Running enumeration scripts can generate
> a significant amount of "noise",
> **potentially triggering anti-virus** or **security monitoring software**.
>
> In some cases, it may be preferable to conduct manual enumeration
> instead.

<!-- WinPEAS-ng {{{-->
### WinPEAS-ng

[WinPEAS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) —
Privilege Escalation Awesome Scripts SUITE (*with colors*)

#### Usage

1. Download the script

```sh
wget https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASps1/winPEAS.ps1 -O winpeas.ps1
```

```sh
wget https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASbat/winPEAS.bat -O winpeas.bat
```

2. Run as binary

```sh
.\winpeas.ps1
```

```sh
.\winpeas.bat
```
<!-- }}} -->

___
<!-- }}} -->
