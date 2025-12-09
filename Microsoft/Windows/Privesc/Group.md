---
id: Group
aliases: []
tags:
  - Microsoft/Windows/Privesc/Group
links: Privesc
---

<!-- Group Enumeration {{{-->
## Group Enumeration

___

<!-- Identify {{{-->
## Identify

<!-- User {{{-->
### User

Enumerate the current user's security groups

<!-- Tip {{{-->
> [!tip]
>
> Check for
>
> - Inherited rights from group membership
> - Active Directory privileges
<!-- }}} -->

[whoami](https://en.wikipedia.org/wiki/Whoami) -
Current user's security groups & [[Privileges|privilege]] status

```sh
whoami /groups
```

<!-- }}} -->

<!-- Local Groups {{{-->
### Local Groups

Identify local groups on the system

<!-- Tip {{{-->
> [!tip]
>
> Check for
>
> - Non-standard groups
> - Misconfigured group membership
<!-- }}} -->

[net localgroup](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11)) -
Local groups

```cmd
net localgroup
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

<!-- }}} -->

<!-- Group Members {{{-->
### Group Members

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

___
<!-- }}} -->

<!-- Privileged Groups {{{-->
## Privileged Groups

> [!todo]

> [!info]- Resources
>
> [HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html)

___
<!-- }}} -->
