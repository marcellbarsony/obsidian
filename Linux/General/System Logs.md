---
id: System Logs
aliases: []
tags:
  - Linux/General/Logs
---

# System Logs

System logs on Linux are a set of files that contain information about the
system and the activities taking place on it.

<!-- Application Logs {{{-->
## Application Logs

Application logs contain information about the activities of specific
applications on the system.

- Apache web server: `/var/log/apache2/error.log`
- MySQL database server: `/var/log/mysql/error.log`
- Nginx: `/var/log/nginx/access.log`
- OpenSSH: `/var/log/auth.log`
- PostgreSQL: `/var/log/postgresql/postgresql-version-main.log`
- Systemd: `/var/log/journal/`

### Access Log Entry

In this log entry, the user `htb-student` used `privileged.sh` script to access
the `api-keys.txt` file in the `/root/hidden/` directory.

```sh
2023-03-07T10:15:23+00:00 servername privileged.sh: htb-student accessed /root/hidden/api-keys.txt
```
<!-- }}} -->

<!-- Authentication Logs {{{-->
## Authentication Logs

Authentication logs (`/var/log/auth.log`) contain information about user
authentication attempts, including successful and failed attempts.

### Auth.log

> [!example]-
> **Auth.log examples**
>
>```sh
>Feb 28 2023 18:15:01 sshd[5678]: Accepted publickey for admin from 10.14.15.2 port 43210 ssh2: RSA SHA256:+KjEzN2cVhIW/5uJpVX9n5OB5zVJ92FtCZxVzzcKjw
>Feb 28 2023 18:15:03 sudo:   admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
>Feb 28 2023 18:15:05 sudo:   admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt-get install netcat-traditional
>Feb 28 2023 18:15:08 sshd[5678]: Disconnected from 10.14.15.2 port 43210 [preauth]
>Feb 28 2023 18:15:12 kernel: [  778.941871] firewall: unexpected traffic allowed on port 22
>Feb 28 2023 18:15:15 auditd[9876]: Audit daemon started successfully
>Feb 28 2023 18:15:18 systemd-logind[1234]: New session 4321 of user admin.
>Feb 28 2023 18:15:21 CRON[2345]: pam_unix(cron:session): session opened for user root by (uid=0)
>Feb 28 2023 18:15:24 CRON[2345]: pam_unix(cron:session): session closed for user root
>```
<!-- }}} -->

<!-- Kernel Logs {{{-->
## Kernel Logs

Kernel logs (`/var/log/kern.log`) contain information about the system's kernel,
including hardware drivers, system calls, and kernel events.

Kernel logs can reveal
- the presence of vulnerable or outdated drivers
- insights into system crashes
- resource limitations
- suspicious system calls
- and other events that could lead to a denial of service.
<!-- }}} -->

<!-- Security Logs {{{-->
## Security Logs

Security logs are often recorded in a veriety of log files:

- Fail2ban: `/var/log/fail2ban.log`
- UFW: `/var/log/ufw.log`
- Other events (changes to system files or settings): `/var/log/syslog` or
  `/var/log/auth.log`
<!-- }}} -->

<!-- System Logs {{{-->
## System Logs

System logs (`/var/log/syslog`) contain information about system-level events,
such as service start and stops, and system reboots.

### Syslog

System logs are located at `/var/log/syslog`

> [!example]-
> **Syslog Example**
>
>```sh
>Feb 28 2023 15:00:01 server CRON[2715]: (root) CMD (/usr/local/bin/backup.sh)
>Feb 28 2023 15:04:22 server sshd[3010]: Failed password for htb-student from 10.14.15.2 port 50223 ssh2
>Feb 28 2023 15:05:02 server kernel: [  138.303596] ata3.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x6 frozen
>Feb 28 2023 15:06:43 server apache2[2904]: 127.0.0.1 - - [28/Feb/2023:15:06:43 +0000] "GET /index.html HTTP/1.1" 200 13484 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
>Feb 28 2023 15:07:19 server sshd[3010]: Accepted password for htb-student from 10.14.15.2 port 50223 ssh2
>Feb 28 2023 15:09:54 server kernel: [  367.543975] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro
>Feb 28 2023 15:12:07 server systemd[1]: Started Clean PHP session files.
>```
<!-- }}} -->

<!-- Systemd {{{-->
## Systemd

### systemd-journald

```sh
journalctl
```

```sh
sudo journalctl -xe
```
<!-- }}} -->
