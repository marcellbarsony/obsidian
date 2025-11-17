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

```sh
sudo pacman -S bluez bluez-utils
```

2. Enable and Start Bluetooth service

```sh
sudo systemctl enable --now bluetooth.service
```

```sh
sudo systemctl start --now bluetooth.service
```
<!-- }}} -->

<!-- Bluetoothctl {{{-->
## Bluetoothctl

Enter `bluetoothctl`

```sh
bluetoothctl
```

```sh
power on
```

```sh
agent on
```

```sh
default-agent
```

### Scan

Scan for devices

```sh
scan on
```

### Pair & Connect

Pair device

```sh
pair 80:C3:BA:70:C8:30
```

Trust device

```sh
trust 80:C3:BA:70:C8:30
```

Connect device

```sh
connect 80:C3:BA:70:C8:30
```

Remove pairing

```sh
remove 80:C3:BA:70:C8:30
```
<!-- }}} -->
