---
id: Privileges
aliases: []
tags:
  - Microsoft/Windows/Privileges/Privileges
links: "[[Windows]]"
---

# Privileges

[Privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
in Windows are rights that an account can be granted
to perform a variety of operations on the local system
(*e.g., managing services, loading drivers,
shutting down the system, debugging an application, etc.*)

**Privileges** are stored in a database
and granted via a [[Access Tokens]]

- Group memberships (*local groups, domain groups*)
- Assigned user rights (*Local Security Policy / GPO*)
- Enabled security policies that map gorups to privileges

An account can have different privileges on different systems
if the account belongs to an [[Active Directory]] domain

Each time a user attempts to perform a privileged action,
the system reviews the user's [[Access Tokens]] to determine
if the account has the required privileges, and if so,
checks to see if they are enabled

<!-- Pvileges vs. Access Rights {{{-->
Privileges vs. Access Rights
> [!info]- Privileges vs. Access Rights
>
> **Privileges** are different from **Access Rights**,
> which a system uses to grant or deny access to securable objects
> (*e.g., folders*)
<!-- }}} -->

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Windows Privilege Abuse: Auditing, Detection, and Defense](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)
> - [4672(S): Special privileges assigned to new logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
<!-- }}} -->

___

<!-- Manage Privileges {{{-->
## Manage Privileges

Enable privileges

[PowerShell Gallery - PoshPrivilege 0.3.0.0](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1)

```powershell
Import-Module .\Enable-Privilege.ps1
```

```powershell
.\Enable-Privilege.ps1
```

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

[GitHub - EnableAllTokenPrivs.ps1](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)

```powershell
.\EnableAllTokenPrivs.ps1
```

<!-- Example {{{-->
> [!example]-
>
> - [GitHub - fashionproof/EnableAllTokenPrivs.ps1](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)
> - [Lee Holmes - Adjusting token privileges in PowerShell](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)
>
> ```powershell
> .\EnableAllTokenPrivs.ps1
> ```
>
> ```powershell
> ## All Credit goes to Lee Holmes (@Lee_Holmes on twitter).  I found the code here https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
> $definition = @'
> using System;
> using System.Collections.Generic;
> using System.Diagnostics;
> using System.Linq;
> using System.Runtime.InteropServices;
>
> namespace Set_TokenPermission
> {
>     public class SetTokenPriv
>     {
>         [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
>         internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
>         ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
>         [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
>         internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
>         [DllImport("advapi32.dll", SetLastError = true)]
>         internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
>         [StructLayout(LayoutKind.Sequential, Pack = 1)]
>         internal struct TokPriv1Luid
>         {
>             public int Count;
>             public long Luid;
>             public int Attr;
>         }
>         internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
>         internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
>         internal const int TOKEN_QUERY = 0x00000008;
>         internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
>         public static void EnablePrivilege()
>         {
>             bool retVal;
>             TokPriv1Luid tp;
>             IntPtr hproc = new IntPtr();
>             hproc = Process.GetCurrentProcess().Handle;
>             IntPtr htok = IntPtr.Zero;
>
>             List<string> privs = new List<string>() {  "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
>             "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
>             "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
>             "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
>             "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
>             "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
>             "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
>             "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
>             "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
>             "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
>             "SeUndockPrivilege", "SeUnsolicitedInputPrivilege", "SeDelegateSessionUserImpersonatePrivilege" };
>
>
>
>
>             retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
>             tp.Count = 1;
>             tp.Luid = 0;
>             tp.Attr = SE_PRIVILEGE_ENABLED;
>
>             foreach (var priv in privs)
>             {
>                 retVal = LookupPrivilegeValue(null, priv, ref tp.Luid);
>                 retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
>             }
>         }
>     }
> }
> '@
>
> $type = Add-Type $definition -PassThru
> $type[0]::EnablePrivilege() 2>&1
> ```
<!-- }}} -->

___
<!-- }}} -->
