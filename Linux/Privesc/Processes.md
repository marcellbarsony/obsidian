---
id: Software Vulnerability
aliases: []
tags:
  - Linux/Privesc/Processes
links: "[[Privesc]]"
---

# Processes

___

<!-- Running Processes {{{-->
## Running Processes

[ps](https://linux.die.net/man/1/ps) —
Snapshot of current processes (*user*)

```sh
ps au
```

[ps](https://linux.die.net/man/1/ps) —
Snapshot of current processes (*`root`*)


```sh
ps aux | grep root
```

[pspy](https://github.com/DominicBreuker/pspy) —
Monitor linux processes without root permissions

```sh
./pspy64 -pf -i 1000
```

<!-- Info {{{-->
> [!info]-
>
> - `-p`: Print commands
> - `-f`: Print filesystem events
> - `-i 1000`: Scan [procfs](https://en.wikipedia.org/wiki/Procfs)
>    every second
<!-- }}} -->


[top](https://linux.die.net/man/1/top) —
Display Linux tasks

```sh
top -n 1
```

<!-- Tip {{{-->
> [!tip]
>
> Check for privileges over the processes binaries
> to potentially overwrite them
<!-- }}} -->

___
<!-- }}} -->

<!-- Process Arguments {{{-->
## Process Arguments

Read command-line arguments of all running processes from `/proc`

```sh
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```

<!-- Example {{{-->
> [!example]-
>
>
> ```sh
> MarciPwns@htb[/htb]$ find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
> ```
>
> ```sh
> ...SNIP...
> startups/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitdroot@10.129.14.200sshroot@10.129.14.200sshd:
> htb-student
> [priv]sshd:
> htb-student
> [priv]/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.ssh/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.sshsshd:
> htb-student@pts/2sshd:
> ```
<!-- }}} -->

Search for [[Secrets]] passed as process arguments
(*suppress `binary file matches` warning*)

```sh
find /proc -name cmdline -exec cat {} \; 2>/dev/null \
 | tr " " "\n" \
 | grep -IaiE 'user|username|pass|password|secret|token|api|key|htb|action'
```

<!-- Info {{{-->
> [!info]-
>
>
> 1. `find /proc` - Search inside the `/proc` filesystem
>
> - `/proc` holds info about running processes,
>   including their command-line arguments
> - `-name cmdline`: Match files named exactly cmdline
>   (*each process has `/proc/<PID>/cmdline*`)
> - `-exec cat {} \;`: Execute `cat` for each file (*`{}`*)
>
> 2. `| tr " " "\n"`: Convert spaces into newline characters
>
> 3. `grep -IaiE` - Search for matching patterns
>
> - `-I`: Ignore binary data
>   (*suppress “binary file matches” warnings*)
> - `-a`: Treat binary input as text
> - `-i`: Case-insensitive search
> - `-E`: Use extended regular expressions
<!-- }}} -->

___
<!-- }}} -->
