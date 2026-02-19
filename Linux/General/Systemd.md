---
id: Systemd
aliases: []
tags:
  - Linux/General/Systemd
---

# Systemd

[Systemd](https://en.wikipedia.org/wiki/Systemd)
is a software suite for system and service management on Linux
built to unify service configuration and behavior across Linux distributions

<!-- Info {{{-->
> [!info]- Resources
>
> - [Arch Wiki](https://wiki.archlinux.org/title/Systemd)
> - [Linux Command Library](https://linuxcommandlibrary.com/man/systemctl)
>
<!-- }}} -->

___

<!-- Usage {{{-->
## Usage

[systemctl](https://man7.org/linux/man-pages/man1/systemctl.1.html) -
Control the systemd system and service manager

Show all running services

```sh
systemctl status
```

List failed units

```sh
systemctl --failed
```

Start/Stop/Restart a service

```sh
systemctl start|stop|restart unit
```

Enable/Disable a service at boot

```sh
systemctl enable|disable unit
```

Reload systemd configuration

```sh
systemctl daemon-reload
```

Check if a unit is active/enabled/failed

```sh
systemctl is-active|is-enabled|is-failed unit
```

List all service units by state

```sh
systemctl list-units --type=service --al
```

List running service units

```sh
systemctl list-units -t service --state running
```

Show contents of a unit file

```sh
systemctl cat unit
```



___
<!-- }}} -->
