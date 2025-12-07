---
id: System Information
aliases: []
tags:
  - Microsoft/Windows/Privesc/System-Information
links: Privesc
---

# System Information

___

<!-- Enumerate System {{{-->
### Enumerate System

Systeminfo

```powershell
systeminfo
```

Find OS Name & Version

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

```powershell
[System.Environment]::OSVersion.Version
```

Patches

```powershell
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

```powershell
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}
```

Security Patches

```powershell
Get-Hotfix -description "Security update"
```

System Architecture

```powershell
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```
___
<!-- }}} -->

<!-- Version Exploits {{{-->
## Version Exploits

> [!tip]
>
> [Microsoft Security Updates](https://msrc.microsoft.com/update-guide/vulnerability)

> [!tip] POC
>
> - [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
> - [abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
> - [SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

___
<!-- }}} -->
