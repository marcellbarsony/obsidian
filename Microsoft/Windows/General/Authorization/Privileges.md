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
and granted via a [[Access Token]]

- Group memberships (*local groups, domain groups*)
- Assigned user rights (*Local Security Policy / GPO*)
- Enabled security policies that map gorups to privileges

An account can have different privileges on different systems
if the account belongs to an [[Active Directory]] domain

Each time a user attempts to perform a privileged action,
the system reviews the user's [[Access Token]] to determine
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
