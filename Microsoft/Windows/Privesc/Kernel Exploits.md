---
id: Kernel Exploits
aliases: []
tags:
  - Microsoft/Windows/Privesc/Kernel-Exploits
links: Privesc
---

# Kernel Exploits

If a host is not being maintained
and running an unpatched or old operating system,
potential kernel vulnerabilities may exist.

___

<!-- Kernel Version {{{-->
## Kernel Version

Check kernel version

```cmd
systeminfo
```
```cmd
ver
```
```cmd
wmic os get version, buildnumber, caption
```

PowerShell — `Get-WmiObject`

```PowerShell
Get-WmiObject Win32_OperatingSystem | Select-Object Version, BuildNumber, Caption
```
___
<!-- }}} -->

<!-- Public Exploits {{{-->
## Public Exploits

Search for publicly available exploits

___
<!-- }}} -->
