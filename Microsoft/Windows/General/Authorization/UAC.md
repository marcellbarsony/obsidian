---
id: UAC
aliases:
  - User Account Control
tags:
  - Microsoft/Windows/General/UAC
links: "[[Microsoft/Windows/Windows]]"
---

# User Account Control (UAC)

**User Account Control** (*[UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)*)
is an access control enforcement feature
that enables a consistent prompt for elevated activities

Applications have different integrity levels and a program with a high level
can perform tasks that could potentially compromise the system

[Microsoft Learn - How User Account Control works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)

<!-- Configuration {{{-->
## Configuration

Administrators can use security policies to configure UAC

- Local: [secpol.msc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/how-to-configure-security-policy-settings)
- [[Microsoft/AD/General]]: [[GPO]]

[Microsoft Learn - User Account Control settings and configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)

___
<!-- }}} -->

<!-- Bypass {{{-->
## Bypass

The [UACME](https://github.com/hfiref0x/UACME) project
maintains UAC bypass techniques

<!-- }}} -->
