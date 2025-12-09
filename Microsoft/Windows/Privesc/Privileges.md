---
id: Privileges
aliases: []
tags:
  - Microsoft/Windows/Privileges
links: "[[Windows]]"
---

# Privileges

[Privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
in Windows are rights that an account can be granted
to perform a variety of operations on the local system
(*e.g., managing services, loading drivers,
shutting down the system, debugging an application, etc.*)

User and group privileges are stored in a database
and granted via an access token when a user logs on to a system

An account can have different privileges on different systems
if the account belongs to an [[Active Directory]] domain

Each time a user attempts to perform a privileged action,
the system reviews the user's access token to see
if the account has the required privileges, and if so,
checks to see if they are enabled

> [!info]- Privileges vs. Access Rights
>
> **Privileges** are different from **Access Rights**,
> which a system uses to grant or deny access to securable objects

___

# Enumeration

<!-- User Privileges {{{-->
## User Privileges

Current user [[Privileges|privileges]]

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

> [!tip]
>
> [[Privileges]]

___
<!-- }}} -->

<!-- Windows Token Privileges {{{-->
# Windows Token Privileges

> [!todo]

<!-- SeImpersonatePrivilege {{{-->
## SeImpersonatePrivilege

> [!todo]

Windows letting a process impersonate the security token of another user

> [!todo]- Resources
> - [SeImpersonatePrivilege - Overview of the impersonate a client after authentication and the create global objects security settings](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege)

> [!tip]
>
> Abuse `SeImpersonatePrivilege` to escalate privileges with
> [Juicypotato](https://github.com/ohpe/juicy-potato)


<!-- }}} -->

<!-- SeAssignPrimaryTokenPrivilege {{{-->
## SeAssignPrimaryTokenPrivilege

> [!todo]

<!-- }}} -->

___
<!-- }}} -->
