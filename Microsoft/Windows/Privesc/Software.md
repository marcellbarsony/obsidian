---
id: Vulnerable Software
aliases: []
tags:
  - Microsoft/Windows/Vulnerable-Software
links: "[[Microsoft/Windows/Windows]]"
---

# Vulnerable Software

Look for public exploits of any installed software,
especially if older, unpatched versions are in use

___

<!-- CMD {{{-->
## CMD

[wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) —
List installed apps

```cmd
wmic product get name, version
```

<!-- Tip {{{-->
> [!tip]-
>
> Enumerate installed programming languages
>
<!-- }}} -->

___
<!-- }}} -->

<!-- PowerShell {{{-->
## PowerShell

[Get-WmiObject](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) —
List installed programs

```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```

[Get-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2025-ps) —
List installed programs (*including Microsoft Store*)

```PowerShell
Get-AppxPackage
```

[Get-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2025-ps) —
List installed programs with details

```PowerShell
Get-AppxPackage | Select Name, PackageFullName
```
___
<!-- }}} -->

<!-- Program Files {{{-->
## Program Files

List `C:\Program Files` for installed software

```sh
dir C:\Program Files
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
