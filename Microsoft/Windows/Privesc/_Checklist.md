---
id: PrivescWin
aliases:
  - PrivescWin
tags:
  - Microsoft/Windows/Privesc
links: "[[Microsoft/Windows/Windows]]"
---

# Windows Privilege Escalation Checklist

___

> [!todo]
>
> Change to the `%TEMP%` directory
> as a large portion of [[Metasploit]]’s Windows privilege escalation modules
> require a file to be written to the target during exploitation
>
> ```sh
> cd %TEMP%
> ```

<!-- Enumeration Tools {{{-->
## Enumeration Tools

- [ ] [[Enumeration Tools]]
    - [ ] [[Enumeration Tools#Enumeration Scripts|Enumeration Scripts]]
        - [ ] [[Enumeration Tools#WinPEAS-ng|WinPEAS-ng]]
        - [ ] [[Enumeration Tools#windows-privesc-check|windows-privesc-check]]
        - [ ] [[Enumeration Tools#PowerSploit|PowerSploit]]
        - [ ] [[Enumeration Tools#JAWS|JAWS]]
        - [ ] [[Enumeration Tools#Sherlock|Sherlock]]

___
<!-- }}} -->

<!-- Kernel Exploits {{{-->
## Kernel Exploits

- [ ] [[Kernel]]
    - [ ] [[Kernel#Kernel Version|Kernel Version]]
    - [ ] [[Kernel#Public Exploits|Public exploits]]

___
<!-- }}} -->

<!-- Installed Software {{{-->
## Installed Software

- [ ] [[Software]]
    - [ ] [[Software#Program Files|Program Files]]
    - [ ] [[Software#PowerShell|PowerShell]]
    - [ ] [[Software#WMIC|WMIC]]
    - [ ] [[Software#LOLBAS|LOLBAS]]

___
<!-- }}} -->

<!-- Exposed credentials {{{-->
## Exposed credentials

- [ ] [[Exposed Credentials]]
    - [ ] [[Exposed Credentials#PowerShell|PowerShell]]
        - [ ] [[Exposed Credentials#History|History]]
        - [ ] [[Exposed Credentials#Logs|Logs]]
        - [ ] [[Exposed Credentials#Profile|Profile]]
    - [ ] [[Exposed Credentials#Credential Manager|Credential Manager]]
    - [ ] [[Exposed Credentials#Application Configuration Files|Application Configuration Files]]
        - [ ] [[Exposed Credentials#INI Files|INI Files]]
        - [ ] [[Exposed Credentials#CONF Files|CONF Files]]
        - [ ] [[Exposed Credentials#XML Files|XML Files]]
        - [ ] [[Exposed Credentials#JSON Files|JSON Files]]
        - [ ] [[Exposed Credentials#YAML/Env Files|YAML/Env Files]]

___
<!-- }}} -->

<!-- User Privileges {{{-->
## User Privileges

> [!todo]

- [ ] [[User Privileges]]
    - [ ] [[User Privileges#Windows Token Privileges|Windows Token Privileges]]
        - [ ] [[User Privileges#SeImpersonatePrivilege|SeImpersonatePrivilege]]
        - [ ] [[User Privileges#SeAssignPrimaryTokenPrivilege|SeAssignPrimaryTokenPrivilege]]

___
<!-- }}} -->

<!-- Scheduled Tasks {{{-->
## Scheduled Tasks

> [!todo]

- [ ] [[Scheduled Tasks]]

___
<!-- }}} -->
