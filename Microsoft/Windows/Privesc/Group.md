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

Enterprise Admins exist only in the root domain of an
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

<!-- }}} -->

<!-- DnsAdmins {{{-->
### DnsAdmins

[DnsAdmins](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#dnsadmins)
have access to network DNS information

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

<!-- }}} -->

<!-- Event Log Readers {{{-->
### Event Log Readers

[Event Log Readers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#event-log-readers)
can read event logs from local computers

```powershell
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
```

<!-- }}} -->

<!-- Hypr-V Administrators {{{-->
### Hypr-V Administrators

[Hypr-V Administrators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#hyper-v-administrators)
have complete and unrestricted access to all the features in
[Hyper-V](https://en.wikipedia.org/wiki/Hyper-V)

```powershell
Get-NetGroupMember -Identity "Hypr-V Administrators" -Recurse
```

<!-- }}} -->

<!-- Print Operators {{{-->
### Print Operators

[Print Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#print-operators)
can manage, create, share, and delete printers
that are connected to a [[Domain Controller]] in the domain

```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

<!-- }}} -->

<!-- Server Operators {{{-->
### Server Operators

[Server Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators)

Members can administer a [[Domain Controller]]

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

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
