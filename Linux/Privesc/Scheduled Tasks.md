---
id: Scheduled Tasks
aliases: []
tags:
  - Linux/Privesc/Scheduled-Tasks
  - Linux/Privesc/Cron
---

# Scheduled Tasks

## Discover Cron

Discover Cron directories

```sh
ls -al /etc/cron*
```

List current user's Cron Jobs

```sh
crontab -l
```

```sh
cat /etc/crontab
```

## Cron Jobs

Check if the following directories have write privilege

- `/etc/cron.d`

```sh
test -w /etc/crontab && echo "Writable" || echo "Not Writable"
```

- `/etc/crontab`

```sh
test -w /etc/cron.d && echo "Writable" || echo "Not Writable"
```

- `/var/spool/cron/crontabs/root`

```sh
test -w /var/spool/cron/crontabs/root && echo "Writable" || echo "Not Writable"
```

> [!todo]
>
> To add Cron Jobs, write a bash script executing a reverse shell command


