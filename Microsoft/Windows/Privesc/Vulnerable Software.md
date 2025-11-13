---
id: Vulnerable Software
aliases: []
tags: []
---

# Vulnerable Software

Look for public exploits of any installed software, especially if older,
unpatched versions are in use.

___

<!-- Program Files {{{-->
## Program Files

Check `C:\Program Files` to see what software is installed

___
<!-- }}} -->

<!-- PowerShell {{{-->
## PowerShell

List installed apps (*including Microsoft Store*)

```PowerShell
Get-AppxPackage
```

List installed apps with details

```PowerShell
Get-AppxPackage | Select Name, PackageFullName
```
___
<!-- }}} -->

<!-- WMIC {{{-->
## WMIC

List installed apps with `wmic`

```cmd
wmic product get name, version
```
___
<!-- }}} -->

<!-- LOLBAS {{{-->
## LOLBAS

[LOLBAS](https://lolbas-project.github.io/#)
contains a list of applications which may be able to perform
certain functions in the context of a privileged user

___
<!-- }}} -->
