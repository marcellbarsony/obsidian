---
id: User
aliases: []
tags:
  - Microsoft/Windows/Privesc/User
links: Privesc
---

<!-- User Enumeration {{{-->
# User Enumeration

___

<!-- Identify {{{-->
## Identify

All local user accounts, groups, privileges

```sh
whoami /all
```

<!-- Current User {{{-->
### Current User

Current user security identity

```sh
whoami
```

Current user from environment variable

```sh
echo %USERNAME%
```

<!-- }}} -->

<!-- Other Users {{{-->
### Other Users

Discover additional user accounts and their rights on the system

> [!tip]-
>
> Lateral movement
>
> - Credential reuse

All local user accounts

```sh
net user
```

```powershell
Get-LocalUser | ft Name,Enabled,LastLogon
```

Full user account details

```powershell
Get-WmiObject -Class Win32_UserAccount
```

<!-- HOME Folders {{{-->
#### HOME Folders

All local user HOME folders

```powershell
Get-ChildItem C:\Users -Force | select Name
```

```powershell
Get-ChildItem C:\Users
```

```cmd
dir C:\Users
```

<!-- }}} -->

<!-- Password Policy {{{-->
#### Password Policy

Password policy

```cmd
net accounts
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> C:\htb> net accounts
> ```
> ```sh
> Force user logoff how long after time expires?:       Never
> Minimum password age (days):                          0
> Maximum password age (days):                          42
> Minimum password length:                              0
> Length of password history maintained:                None
> Lockout threshold:                                    Never
> Lockout duration (minutes):                           30
> Lockout observation window (minutes):                 30
> Computer role:                                        SERVER
> The command completed successfully.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Sessions {{{-->
#### Sessions

Logged in users & sessions

```sh
query user
```

Active RDP/terminal service sessions & states

```sh
qwinsta
```

Current [[Kerberos]] logon sessions and tickets

```sh
klist sessions
```

<!-- }}} -->

<!-- Specific User {{{-->
#### Specific User

Specific user account info

```sh
net users %username%
```

<!-- }}} -->

<!-- }}} -->

<!-- }}} -->
