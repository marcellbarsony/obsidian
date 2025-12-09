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
## Enumerate System

> [!tip]
>
> [Microsoft Security Updates](https://msrc.microsoft.com/update-guide/vulnerability)

[systeminfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo) —
Display detailed configuration information about a computer
and its operating system

```powershell
systeminfo
```

```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

[System.Environment](https://learn.microsoft.com/en-us/dynamics365/business-central/application/system/namespace/system.environment)
Namespace — Provides core environment management functionality

```powershell
[System.Environment]::OSVersion.Version
```

[Get-WmiObject](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) —
Gets instances of Windows Management Instrumentation (*WMI*) classes

```powershell
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
```

> [!tip] POC
>
> - [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
> - [abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
> - [SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

___
<!-- }}} -->

<!-- Architecture {{{-->
## Architecture

System Architecture

[wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) —
A command-line interface for Windows Management Instrumentation (WMI)

```powershell
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```
___
<!-- }}} -->

<!-- Security Patches {{{-->
## Security Patches

[wmic](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) —
List Security Patches

```sh
wmic qfe
```

```sh
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

[Get-WmiObject](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) —
List Security Patches

```powershell
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}
```

[Get-Hotfix](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.5&viewFallbackFrom=powershell-7.1) —
Gets the hotfixes that are installed on local or remote computers

```powershell
Get-HotFix | ft -AutoSize
```

```powershell
Get-Hotfix -description "Security update"
```

<!-- Tip {{{-->
> [!tip]-
>
> - Get Patch Level
> - Search the web for the KB's under
>   [HotFixes](https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix)
>   to determine when the machine has been patched
<!-- }}} -->

___
<!-- }}} -->
