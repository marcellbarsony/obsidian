---
id: Privesc
aliases:
  - Privesc
tags:
  - Microsoft/Windows/Privesc
links: "[[Microsoft/Windows/Windows]]"
---

# Windows Privilege Escalation

The goal of the privilege escalation is to gain access
to a given system to a member of the Local Administrators group
or the `NT AUTHORITY` \ `SYSTEM` [LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
account

Privilege Escalation may be necessary

1. When testing a client's [golden image](https://www.redhat.com/en/topics/linux/what-is-a-golden-image)
   Windows workstation and server build for flaws
2. To escalate privileges locally to gain access to some local resource
   (*e.g., a database*)
3. To gain [NT AUTHORITY\System](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
   level access on a domain-joined machine
   to gain a foothold into the client's [[Microsoft/AD/General]] environment
4. To obtain credentials to move laterally
   or escalate privileges within the client's network

> [!info] Resources
>
> [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

___

