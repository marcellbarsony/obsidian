---
id: Scheduled Tasks
aliases: []
tags:
  - Linux/Privesc/Scheduled-Tasks
  - Linux/Privesc/Cron-Jobs
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
ls -al /etc/cron.d/
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
ls -al /var/spool/cron/
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

<!-- Tip {{{-->
> [!tip]
>
> Investigate [[Processes#Running Processes|Running Processes]]
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> - A Cron Job runs `/dmz-backups/backup.sh`
> - `backup.sh` creates a tarball file of the contents of `/var/www/html`
>
> ```sh
> ./pspy64 -pf -i 1000
> ```
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

___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

<!-- Write Privilege {{{-->
### Write Privilege

Check if the any of the Cron directories or its files have write privilege set

`/etc/cron.d`

```sh
test -w /etc/cron.d && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.d -type f -perm -0002 -ls
```

```sh
for g in $(id -Gn); do find /etc/cron.d -type f -perm -0020 -group "$g" -ls; done
```

`/etc/cron.hourly`

```sh
test -w /etc/cron.hourly && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.hourly -type f -perm -0002 -ls
```

`/etc/cron.daily/`

```sh
test -w /etc/cron.daily && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.daily -type f -perm -0002 -ls
```

`/etc/cron.weekly/`

```sh
test -w /etc/cron.weekly && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.weekly -type f -perm -0002 -ls
```

`/etc/cron.monthly/`

```sh
test -w /etc/cron.monthly && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/cron.monthly -type f -perm -0002 -ls
```

`/etc/crontab`

```sh
test -w /etc/crontab && echo "Writable" || echo "Not Writable"
```

```sh
find /etc/corontab -type f -perm -0002 -ls
```

`/var/spool/cron`

```sh
test -w /var/spool/cron && echo "Writable" || echo "Not Writable"
```

```sh
find /var/spool/cron -type f -perm -0002 -ls
```

`/var/spool/cron/crontabs/root`

```sh
test -w /var/spool/cron/crontabs/root && echo "Writable" || echo "Not Writable"
```

```sh
find /var/spool/cron/crontabs/root -type f -perm -0002 -ls
```

<!-- Tip {{{-->
> [!tip]
>
> Find [[Directory & File#Writable Directories|Writable Directories]] &
> [[Directory & File#Writable|Writable Files]]
<!-- }}} -->

<!-- }}} -->

<!-- Writable Scripts {{{-->
### Writable Scripts

Check the [[Directory & File#Writable|writability]]
of the scripts executed by Cron Jobs

```sh
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

<!-- Tip {{{-->
> [!tip]-
>
> Append a [RevShell](https://www.revshells.com/)
> to the script to spawn a `root` shell
<!-- }}} -->

<!-- }}} -->

<!-- Wildcard Abuse {{{-->
### Wildcard Abuse

Wildcards in Cron Jobs may expand filenames to command arguments

> [!example] [[Wildcard Abuse]]

<!-- }}} -->

___
<!-- }}} -->
