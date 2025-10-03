---
id: Bluetooth
aliases: []
tags: []
---

# Bluetooth

<!-- Installation {{{-->
## Installation

```sh
sudo pacman -S bluez bluez-utils
```
<!-- }}} -->

<!-- Service {{{-->
## Service

Enable and Start Bluetooth service

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
