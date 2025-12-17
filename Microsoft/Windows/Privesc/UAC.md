
# User Account Control

<!-- Enumeration {{{-->
## Enumeration

1. Check current user

```sh
whoami /user
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> whoami /user
> ```
>
> ```sh
> USER INFORMATION
> ----------------
>
> User Name         SID
> ================= ==============================================
> winlpe-ws03\sarah S-1-5-21-3159276091-2191180989-3781274054-1002
> ```
<!-- }}} -->

2. Confirm admin group membership

```sh
net localgroup administrators
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> net localgroup administrators
> ```
>
> ```sh
> Alias name     administrators
> Comment        Administrators have complete and unrestricted access to the computer/domain
>
> Members
>
> -------------------------------------------------------------------------------
> Administrator
> mrb3n
> sarah
> The command completed successfully.
> ```
<!-- }}} -->

3. Review user privileges

```sh
whoami /priv
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> whoami /priv
> ```
>
> ```sh
> PRIVILEGES INFORMATION
> ----------------------
>
> Privilege Name                Description                          State
> ============================= ==================================== ========
> SeShutdownPrivilege           Shut down the system                 Disabled
> SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
> SeUndockPrivilege             Remove computer from docking station Disabled
> SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
> SeTimeZonePrivilege           Change the time zone                 Disabled
> ```
<!-- }}} -->

4. Confirm if UAC is enabled

There is no command-line version of the GUI consent prompt,
UAC should be bypassed with privileged access token

```sh
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
> ```
>
> ```sh
> HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
>     EnableLUA    REG_DWORD    0x1
> ```
<!-- }}} -->

5. Check UAC Level

```sh
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

<!-- Example {{{-->
> [!example]-
>
> `ConsentPromptBehaviorAdmin` is `0x5`
> which means the highest [[UAC]] level of `Always notify` is enabled
>
> ```sh
> C:\htb> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
> ```
> ```sh
> HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
>     ConsentPromptBehaviorAdmin    REG_DWORD    0x5
> ```
<!-- }}} -->

6. Check Windows version


```powershell
[environment]::OSVersion.Version
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> [environment]::OSVersion.Version
> ```
>
> ```powershell
> Major  Minor  Build  Revision
> -----  -----  -----  --------
> 10     0      14393  0
> ```
<!-- }}} -->

7. [Windows 10 version history](https://en.wikipedia.org/wiki/Windows_10_version_history) —
Cross-reference build version with release version

___
<!-- }}} -->

<!-- Bypass {{{-->
## Bypass

The [UACME](https://github.com/hfiref0x/UACME) project
maintains a list of UAC bypasses

___
<!-- }}} -->
