---
id: Nagios
aliases: []
tags:
  - Linux/General/Software/Nagios
---

# Nagios

[Nagios](https://en.wikipedia.org/wiki/Nagios)
is an open source event monitoring and network management system
that offers monitoring and alerting services for servers,
switches, applications and services

___

<!-- Vulnerabilities {{{-->
## Vulnerabilities

### CVE-2016-9566

[CVE-2016-9566](https://www.cve.org/CVERecord?id=CVE-2016-9566) -
`base/logging.c` in Nagios Core (< `4.2.4`) allows local users
with access to an account in the nagios group to gain root privileges
via a symlink attack on the log file.

<!-- Tip {{{-->
> [!tip]
>
> This can be leveraged by remote attackers using
> [CVE-2016-9565](https://www.cve.org/CVERecord?id=CVE-2016-9565)
<!-- }}} -->


<!-- Public Exploit {{{-->
> [!tip] Public Exploit
>
> Exploit DB
> [Nagios XI 5.5.6 - Remote Code Execution / Privilege Escalation](https://www.exploit-db.com/exploits/40921)
<!-- }}} -->

___
<!-- }}} -->
