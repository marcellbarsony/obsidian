---
id: Bluetooth
aliases: []
tags:
  - Linux/General/Audio/Bluetooth
---

# Bluetooth

<!-- Installation {{{-->
## Installation

1. Install the following packages:

- [bluez](https://archlinux.org/packages/extra/x86_64/bluez/),
  providing the Bluetooth protocol stack

- [bluez-utils](https://archlinux.org/packages/extra/x86_64/bluez-utils/),
  providing the bluetoothctl utility

> [!example]
>
>```sh
>sudo pacman -S bluez bluez-utils
>```

2. Enable and Start Bluetooth service

> [!example]
>
>```sh
>sudo systemctl enable --now bluetooth.service
>```
>
>```sh
>sudo systemctl start --now bluetooth.service
>```
<!-- }}} -->

<!-- Bluetoothctl {{{-->
## Bluetoothctl

Enter `bluetoothctl`

```sh
bluetoothctl
power on
agent on
default-agent
```

### Scan

Scan for devices

```sh
scan on
```

### Pair & Connect

Pair, Trust & Connect

```sh
pair 80:C3:BA:70:C8:30
trust 80:C3:BA:70:C8:30
connect 80:C3:BA:70:C8:30
```

Remove pairing

```sh
remove 80:C3:BA:70:C8:30
```
<!-- }}} -->
