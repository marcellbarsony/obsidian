---
id: Access Token
aliases: []
tags:
  - Microsoft/Windows/Authorization/Access-Token
links: "[[Microsoft/Windows/Windows]]"
---

# Access Token

[Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
used to describe the security context (*security attributes or rules*)
of a process or thread

1. [Winlogon](https://en.wikipedia.org/wiki/Winlogon)
   presents the login UI
2. The user logs in
3. Credentials are verified by [[Processes/Processes#LSASS|LSASS]]
4. Authentication providers check credentials (*Kerberos, NTLM, etc.*)
5. [[Processes/Processes#LSASS|LSASS]] builds the [[Access Tokens]]
6. [Winlogon](https://en.wikipedia.org/wiki/Winlogon)
   starts the user session with the token
7. `Userinit.exe`/`Explorer.exe` launch under the token


___

<!-- Processes {{{-->
## Processes

Every [[Processes/Processes|process]] executed on behalf of a user
has a copy of the access token

Every time a user interacts with a process,
a copy of the token will be presented to determine their privilege level

The token includes information about the user account's identity
and [[Microsoft/Windows/General/Authorization/Privileges|Privileges]] related to a specific process or thread

___
<!-- }}} -->

<!-- Contents {{{-->
## Contents

**Access Tokns** contain the following informatoin

- User account's
  [SID](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers)
  (*security identifier*)
- Group [SID](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers)(s) -
  (*local & domain groups for which the user is a member*)
- Logon `SID`
  (*identifies the logon session*)
- [[Microsoft/Windows/General/Authorization/Privileges|Privileges]]
  (*held by the user or user's groups*)
- Default [DACL](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
  (*defines default permissions for newly created objects*)
- User access rights (*Local Security Policy / GPO*)
- Token type (*primary or impersonation*)

___
<!-- }}} -->
