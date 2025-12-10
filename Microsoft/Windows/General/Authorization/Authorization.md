---
id: Authorization
aliases: []
tags:
  - Microsoft/Windows/Authorization
links: "[[Windows]]"
---

# Authorization

___

## Authorization Process

**Security Principals** are the primary way of controlling access
to resources on Windows hosts

**Security Principals** are identified by a unique
[Security Identifier (SID)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)

The [[Access Token]]
is compared against
[Access Control Entries (ACEs)](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries)
within the object's
[security descriptor](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)
(*which contains security information about a securable object
(e.g., access rights)*) granted to users or groups

![[auth_process.png]]

<!-- Rights & Privileges {{{-->
## Rights & Privileges

Groups that grant their members powerful rights and privileges
can be abused to escalate privileges

<!-- Groups {{{-->
> [!info]- Groups
>
> | Group | Description |
> | --- | --- |
> | Server Operators            | Members can modify services, access SMB shares, and backup files |
> | Backup Operators            | Members are allowed to log onto DCs locally and should be considered Domain Admins They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB  This group is sometimes added to the local Backup Operators group on non-DCs |
> | Print Operators             | Members can log on to DCs locally and "trick" Windows into loading a malicious driver |
> | Hyper-V Administrators      | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins |
> | Account Operators           | Members can modify non-protected accounts and groups in the domain |
> | Remote Desktop Users        | Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol |
> | Remote Management Users     | Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs) |
> | Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU |
> | Schema Admins               | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL |
> | DNS Admins                  | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server They can load a malicious DLL and wait for a reboot as a persistence mechanism  Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record |
<!-- }}} -->

<!-- }}} -->
