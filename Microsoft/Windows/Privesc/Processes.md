---
id: Processes
aliases:
  - Processes
tags:
  - Microsoft/Windows/Processes
links: "[[Windows]]"
---

# Process Enumeration

___

<!-- Identify {{{-->
## Identify

> [!tip]
>
> [[General/Processes#Standard Processes|Windows Standard Processes]]

[tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) —
Running processes and services

```sh
Tasklist /svc
```

```sh
tasklist /v /fi "username eq system"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> tasklist /svc
> ```
>
> ```sh
> Image Name                     PID Services
> ========================= ======== ============================================
> System Idle Process              0 N/A
> System                           4 N/A
> smss.exe                       316 N/A
> csrss.exe                      424 N/A
> wininit.exe                    528 N/A
> csrss.exe                      540 N/A
> winlogon.exe                   612 N/A
> services.exe                   664 N/A
> lsass.exe                      672 KeyIso, SamSs, VaultSvc
> svchost.exe                    776 BrokerInfrastructure, DcomLaunch, LSM,
>                                    PlugPlay, Power, SystemEventsBroker
> svchost.exe                    836 RpcEptMapper, RpcSs
> LogonUI.exe                    952 N/A
> dwm.exe                        964 N/A
> svchost.exe                    972 TermService
> svchost.exe                   1008 Dhcp, EventLog, lmhosts, TimeBrokerSvc
> svchost.exe                    364 NcbService, PcaSvc, ScDeviceEnum, TrkWks,
>                                    UALSVC, UmRdpService
> <...SNIP...>
>
> svchost.exe                   1468 Wcmsvc
> svchost.exe                   1804 PolicyAgent
> spoolsv.exe                   1884 Spooler
> svchost.exe                   1988 W3SVC, WAS
> svchost.exe                   1996 ftpsvc
> svchost.exe                   2004 AppHostSvc
> FileZilla Server.exe          1140 FileZilla Server
> inetinfo.exe                  1164 IISADMIN
> svchost.exe                   1736 DiagTrack
> svchost.exe                   2084 StateRepository, tiledatamodelsvc
> VGAuthService.exe             2100 VGAuthService
> vmtoolsd.exe                  2112 VMTools
> MsMpEng.exe                   2136 WinDefend
>
> <...SNIP...>
>
> FileZilla Server Interfac     5628 N/A
> jusched.exe                   5796 N/A
> cmd.exe                       4132 N/A
> conhost.exe                   4136 N/A
> TrustedInstaller.exe          1120 TrustedInstaller
> TiWorker.exe                  1816 N/A
> WmiApSrv.exe                  2428 wmiApSrv
> tasklist.exe                  3596 N/A
> ```
<!-- }}} -->

With allowed usernames

```powershell
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

Without usernames

```powershell
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

> [!tip]
>
> Check for running
> [electron/cef/chromium debuggers](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.html)

___
<!-- }}} -->

<!-- Permissions {{{-->
## Permissions

> [!tip]
>
> [[DLL Hijacking]]


Process binary permissions

```sh
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
        icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
    )
)
```

Process binary folder permissions

```sh
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

___
<!-- }}} -->

<!-- Access Tokens {{{-->
## Access Tokens

[AccessTokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
used to describe the security context (*security attributes or rules*)
of a process or thread.

The token includes information about the user account's identity
and privileges related to a specific process or thread.

When a user authenticates to a system, their password is verified
against a security database, and if properly authenticated,
they will be assigned an access token.

Every time a user interacts with a process,
a copy of this token will be presented to determine their privilege level.

___
<!-- }}} -->

<!-- Named Pipes {{{-->
## Named Pipes

[Named Pipes](https://en.wikipedia.org/wiki/Named_pipe) (*a.k.a FIFO*)
on Windows are files stored in memory that get cleared out after being read
and is one of the methods of inter-process communication
(*[IPC](https://en.wikipedia.org/wiki/Inter-process_communication)*)

> [!example]
>
> ```sh
> \\.\PipeName\\ExampleNamedPipeServer
> ```

<!-- Pipe Communication {{{-->
### Pipe Communication

Windows systems use a Client-Server implementation

- **SERVER**: The process that creates a named pipe
- **CLIENT**: The process communicating with the named pipe

Named pipes can communicate using

- **half-duplex** (*one-way*) channel
  with the client only being able to write data to the server
- **duplex** (*two-way*) channel
  that allows the client to write data over the pipe,
  and the server to respond back with data

Every active connection to a named pipe server
results in the creation of a new named pipe

<!-- }}} -->

<!-- Enumeration {{{-->
### Enumeration

[PipeList](https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist) —
List named pipes

```sh
pipelist.exe /accepteula
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> pipelist.exe /accepteula
> ```
>
> ```sh
> PipeList v1.02 - Lists open named pipes
> Copyright (C) 2005-2016 Mark Russinovich
> Sysinternals - www.sysinternals.com
>
> Pipe Name                                    Instances       Max Instances
> ---------                                    ---------       -------------
> InitShutdown                                      3               -1
> lsass                                             4               -1
> ntsvcs                                            3               -1
> scerpc                                            3               -1
> Winsock2\CatalogChangeListener-340-0              1                1
> Winsock2\CatalogChangeListener-414-0              1                1
> epmapper                                          3               -1
> Winsock2\CatalogChangeListener-3ec-0              1                1
> Winsock2\CatalogChangeListener-44c-0              1                1
> LSM_API_service                                   3               -1
> atsvc                                             3               -1
> Winsock2\CatalogChangeListener-5e0-0              1                1
> eventlog                                          3               -1
> Winsock2\CatalogChangeListener-6a8-0              1                1
> spoolss                                           3               -1
> Winsock2\CatalogChangeListener-ec0-0              1                1
> wkssvc                                            4               -1
> trkwks                                            3               -1
> vmware-usbarbpipe                                 5               -1
> srvsvc                                            4               -1
> ROUTER                                            3               -1
> vmware-authdpipe                                  1                1
>
> <SNIP>
> ```
<!-- }}} -->

[Get-Childitem](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-7.5) —
List named pipes

```powershell
gci \\.\pipe\
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb>  gci \\.\pipe\
> ```
>
> ```powershell
>     Directory: \\.\pipe
>
>
> Mode                LastWriteTime         Length Name
> ----                -------------         ------ ----
> ------       12/31/1600   4:00 PM              3 InitShutdown
> ------       12/31/1600   4:00 PM              4 lsass
> ------       12/31/1600   4:00 PM              3 ntsvcs
> ------       12/31/1600   4:00 PM              3 scerpc
>
>
>     Directory: \\.\pipe\Winsock2
>
>
> Mode                LastWriteTime         Length Name
> ----                -------------         ------ ----
> ------       12/31/1600   4:00 PM              1 Winsock2\CatalogChangeListener-34c-0
>
>
>     Directory: \\.\pipe
>
>
> Mode                LastWriteTime         Length Name
> ----                -------------         ------ ----
> ------       12/31/1600   4:00 PM              3 epmapper
>
> <SNIP>
> ```
<!-- }}} -->

<!-- Permissions {{{-->
#### Permissions

Enumerate permissions assigned to a specific named pipe

<!-- Example {{{-->
> [!example]-
>
> Only administrators have full access to the LSASS process
>
> ```sh
> C:\htb> accesschk.exe /accepteula \\.\Pipe\lsass -v
> ```
>
> ```sh
> Accesschk v6.12 - Reports effective permissions for securable objects
> Copyright (C) 2006-2017 Mark Russinovich
> Sysinternals - www.sysinternals.com
>
> \\.\Pipe\lsass
>   Untrusted Mandatory Level [No-Write-Up]
>   RW Everyone
>         FILE_READ_ATTRIBUTES
>         FILE_READ_DATA
>         FILE_READ_EA
>         FILE_WRITE_ATTRIBUTES
>         FILE_WRITE_DATA
>         FILE_WRITE_EA
>         SYNCHRONIZE
>         READ_CONTROL
>   RW NT AUTHORITY\ANONYMOUS LOGON
>         FILE_READ_ATTRIBUTES
>         FILE_READ_DATA
>         FILE_READ_EA
>         FILE_WRITE_ATTRIBUTES
>         FILE_WRITE_DATA
>         FILE_WRITE_EA
>         SYNCHRONIZE
>         READ_CONTROL
>   RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
>         FILE_READ_ATTRIBUTES
>         FILE_READ_DATA
>         FILE_READ_EA
>         FILE_WRITE_ATTRIBUTES
>         FILE_WRITE_DATA
>         FILE_WRITE_EA
>         SYNCHRONIZE
>         READ_CONTROL
>   RW BUILTIN\Administrators
>         FILE_ALL_ACCESS
> ```
<!-- }}} -->

[AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) —
Enumerate all named pipes that allow write access with a command

```sh
accesschk.exe -w \pipe\* -v
```

[AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) —
Enumerate a process's permissions by reviewing the Discretionary Access List (DACL)

```sh
accesschk.exe /accepteula \\.\Pipe\<process> -v
```

<!-- }}} -->

<!-- }}} -->

<!-- Exploitation {{{-->
### Exploitation

[Exploit-DB - WindscribeService Named Pipe Privilege Escalation](https://www.exploit-db.com/exploits/48021)

<!-- Example {{{-->
> [!example]-
>
> - The `WindscribeService` named pipe allows `READ` and `WRITE` access
>   to the `Everyone` group
> - The `Everyone` group has `FILE_ALL_ACCESS` over the pipe
>
> ```sh
> C:\htb> accesschk.exe -accepteula -w \pipe\WindscribeService -v
> ```
> ```sh
> Accesschk v6.13 - Reports effective permissions for securable objects
> Copyright ⌐ 2006-2020 Mark Russinovich
> Sysinternals - www.sysinternals.com
>
> \\.\Pipe\WindscribeService
>   Medium Mandatory Level (Default) [No-Write-Up]
>   RW Everyone
>         FILE_ALL_ACCESS
> ```
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
