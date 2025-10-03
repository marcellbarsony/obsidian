---
id: Bluetooth Audio
aliases: []
tags: []
---

# PipeWire

<!-- Installation {{{-->
## Installation

Install [Pipewire](https://wiki.archlinux.org/title/PipeWire#Installation)

```sh
sudo pacman -S pipewire pipewire-pulse wireplumber
```
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

Default configurations should be copied from `/usr/share/pipewire` to
`~/.config/pipewire/`.
<!-- }}} -->

<!-- WirePlumber {{{-->
## WirePlumber

### Objects

Show all objects managed by WirePlumber

```sh
wpctl status
```

Obtain interface name for rules matching ([Arch Wiki](https://wiki.archlinux.org/title/WirePlumber#Obtain_interface_name_for_rules_matching))

> [!example]-
>
>```sh
>PipeWire 'pipewire-0' [0.3.56, user@hostname, cookie:1163266174]
>
>Audio
> ├─ Devices:
> │      ...
> │
> ├─ Sinks:
> │  *   60. MOMENTUM 4  [vol: 0.50]
> │
> ├─ ...
>```

View the object's detail and list all properties in that object

```sh
wpctl inspect 60
```

[Freedesktop.org - WirePlumber 0.5.11 - Bluetooth Configuration](https://pipewire.pages.freedesktop.org/wireplumber/daemon/configuration/bluetooth.htm)

Choose the `device.name` or `node.name` property to use with the matches rules
in the configuration

<!-- Example {{{-->
> [!example]-
>
>```sh
>id 60, type PipeWire:Interface:Node
>    api.bluez5.address = "80:C3:BA:70:C8:30"
>    api.bluez5.codec = "aptx_hd"
>    api.bluez5.profile = "a2dp-sink"
>    api.bluez5.transport = ""
>    bluez5.loopback = "false"
>    card.profile.device = "1"
>  * client.id = "40"
>    clock.quantum-limit = "8192"
>    device.api = "bluez5"
>  * device.id = "50"
>    device.routes = "1"
>  * factory.id = "12"
>    factory.name = "api.bluez5.a2dp.sink"
>    library.name = "audioconvert/libspa-audioconvert"
>  * media.class = "Audio/Sink"
>    media.name = "MOMENTUM 4"
>  * node.description = "MOMENTUM 4"
>    node.driver = "true"
>    node.driver-id = "60"
>    node.loop.name = "data-loop.0"
>  * node.name = "bluez_output.80_C3_BA_70_C8_30.1"
>    node.pause-on-idle = "false"
>  * object.serial = "1656"
>    port.group = "stream.0"
>  * priority.driver = "1010"
>  * priority.session = "1010"
>    spa.object.id = "1"
>```
<!-- }}} -->

> [!note]
> Lua configs are deprecated and will not work
<!--}}}-->
