---
id: Privileges
aliases: []
tags:
  - Microsoft/Windows/Privileges
links: "[[Windows]]"
---

# Privilege Enumeration

Enumerate [[Microsoft/Windows/General/Authorization/Privileges|Privileges]]

___

<!-- User Privileges {{{-->
## User Privileges

Current user privileges

> [!tip]
>
> Some privileges are only available when running an elevated
> `cmd` or `PowerShell` session

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
> Privilege Name                Description                    State
> ============================= ============================== ========
> SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
> SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
> ```
<!-- }}} -->

```powershell
Get-LocalUser | Select-Object *
```

___
<!-- }}} -->

<!-- Windows Token Privileges {{{-->
# Windows Token Privileges

___

<!-- Enable Privileges {{{-->
## Enable Privileges

Enabling privileges requires PowerShell scripts

<!-- Example {{{-->
> [!example]-
>
> [PowerShell Gallery - PoshPrivilege 0.3.0.0](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1)
>
> ```powershell
> Function Enable-Privilege {
>     <#
>         .SYNOPSIS
>             Enables specific privilege or privileges on the current process.
>
>         .DESCRIPTION
>             Enables specific privilege or privileges on the current process.
>
>         .PARAMETER Privilege
>             Specific privilege/s to enable on the current process
>
>         .NOTES
>             Name: Enable-Privilege
>             Author: Boe Prox
>             Version History:
>                 1.0 - Initial Version
>
>         .EXAMPLE
>         Enable-Privilege -Privilege SeBackupPrivilege
>
>         Description
>         -----------
>         Enables the SeBackupPrivilege on the existing process
>
>         .EXAMPLE
>         Enable-Privilege -Privilege SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege
>
>         Description
>         -----------
>         Enables the SeBackupPrivilege, SeRestorePrivilege and SeTakeOwnershipPrivilege on the existing process
>
>     #>
>     [cmdletbinding(
>         SupportsShouldProcess = $True
>     )]
>     Param (
>         [parameter(Mandatory = $True)]
>         [Privileges[]]$Privilege
>     )
>     If ($PSCmdlet.ShouldProcess("Process ID: $PID", "Enable Privilege(s): $($Privilege -join ', ')")) {
>         #region Constants
>         $SE_PRIVILEGE_ENABLED = 0x00000002
>         $SE_PRIVILEGE_DISABLED = 0x00000000
>         $TOKEN_QUERY = 0x00000008
>         $TOKEN_ADJUST_PRIVILEGES = 0x00000020
>         #endregion Constants
>
>         $TokenPriv = New-Object TokPriv1Luid
>         $HandleToken = [intptr]::Zero
>         $TokenPriv.Count = 1
>         $TokenPriv.Attr = $SE_PRIVILEGE_ENABLED
>
>         #Open the process token
>         $Return = [PoshPrivilege]::OpenProcessToken(
>             [PoshPrivilege]::GetCurrentProcess(),
>             ($TOKEN_QUERY -BOR $TOKEN_ADJUST_PRIVILEGES), 
>             [ref]$HandleToken
>         )
>         If (-NOT $Return) {
>             Write-Warning "Unable to open process token! Aborting!"
>             Break
>         }
>         ForEach ($Priv in $Privilege) {
>             $PrivValue = $Null
>             $TokenPriv.Luid = 0
>             #Lookup privilege value
>             $Return = [PoshPrivilege]::LookupPrivilegeValue($Null, $Priv, [ref]$PrivValue)             
>             If ($Return) {
>                 $TokenPriv.Luid = $PrivValue
>                 #Adjust the process privilege value
>                 $return = [PoshPrivilege]::AdjustTokenPrivileges(
>                     $HandleToken, 
>                     $False, 
>                     [ref]$TokenPriv, 
>                     [System.Runtime.InteropServices.Marshal]::SizeOf($TokenPriv), 
>                     [IntPtr]::Zero, 
>                     [IntPtr]::Zero
>                 )
>                 If (-NOT $Return) {
>                     Write-Warning "Unable to enable privilege <$priv>! "
>                 }
>             }
>         }
>     }
> }
> ```
<!-- }}} -->

___
<!-- }}} -->

## Exploitation

In Windows, every process has a token
that has information about the account that is running it

These tokens are not considered secure resources,
as they are just locations within memory
that could be brute-forced by users that cannot read memory

<!-- Resources {{{-->
> [!info] Resources
>
> - [HackTricks - Abusing Tokens](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html)
<!-- }}} -->

<!-- SeAssignPrimaryTokenPrivilege {{{-->
### SeAssignPrimaryTokenPrivilege

> [!todo]

<!-- }}} -->

<!-- SeImpersonatePrivilege {{{-->
### SeImpersonatePrivilege

> [!todo]

Windows letting a process impersonate the security token of another user

> [!warning]
>
> `SeImpersonatePrivilege` is only given to administrative accounts

> [!todo]- Resources
>
> - [SeImpersonatePrivilege - Overview of the impersonate a client after authentication and the create global objects security settings](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege)

> [!tip]
>
> Abuse `SeImpersonatePrivilege` to escalate privileges with
> [Juicypotato](https://github.com/ohpe/juicy-potato)
> or
> [RoguePotato](https://github.com/antonioCoco/RoguePotato)

<!-- }}} -->

<!-- SeDebugPrivilege {{{-->
### SeDebugPrivilege

> [!todo]

<!-- }}} -->

<!-- SeTakeOwnerShipPrivilege {{{-->
### SeTakeOwnerShipPrivilege

> [!todo]

<!-- }}} -->

___
<!-- }}} -->
