---
id: PipeWire
aliases: []
tags:
  - Linux/General/Audio/PipeWire
---

# PipeWire

[PipeWire](https://pipewire.org/) is a project that aims to greatly improve
handling of audio and video under Linux. It provides a low-latency, graph-based
processing engine on top of audio and video devices that can be used to support
the use cases currently handled by both PulseAudio and JACK. PipeWire was
designed with a powerful security model that makes interacting with audio and
video devices from containerized applications easy, with support for Flatpak
applications being the primary goal. Alongside Wayland and Flatpak, we expect
PipeWire to provide a core building block for the future of Linux application
development.

- Capture and playback of audio and video with minimal latency.
- Real-time multimedia processing on audio and video.
- Multiprocess architecture to let applications share multimedia content.
- Seamless support for PulseAudio, JACK, ALSA, and GStreamer applications.
- Sandboxed applications support. See Flatpak for more info.

## ALSA vs. PipeWire

Some may describe this as "replacing ALSA", but as the [PipeWire FAQ](https://gitlab.freedesktop.org/pipewire/pipewire/-/wikis/FAQ)
clarifies:

> [!quote]
>No, ALSA is an essential part of the Linux audio stack, it provides the
>interface to the kernel audio drivers

That said, the [ALSA](https://www.alsa-project.org/wiki/Main_Page) user space
library has a lot of stuff in it that is probably not desirable anymore these
days, like effects plugins, mixing, routing, slaving, etc. PipeWire uses a small
subset of the core ALSA functionality to access the hardware. All of the other
features should be handled by PipeWire.

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

For configuration options read the [PipeWire Docs](https://docs.pipewire.org/)

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
