---
id: WireGuard
aliases: []
tags:
  - Linux/General/Networking/WireGuard
---

# WireGuard

**[WireGuard](https://wiki.archlinux.org/title/WireGuard)** is a simple yet fast
general purpose VPN.

<!-- Installation {{{-->
## Installation

Install the [wireguard-tools](https://archlinux.org/packages/?name=wireguard-tools)
package for userspace utilities

> [!example]
>
>```sh
>sudo pacman -S wireguard-tools
>```
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

1. Switch to `root`

> [!example]
>
>```sh
>sudo su
>```

2. Copy VPN configuration (e.g. *[ProtonVPN](https://account.proton.me/u/0/vpn/WireGuard)*)

> [!example]
>
>```sh
>cp /home/user/Downloads/wg0.conf /etc/wireguard
>ls -al /etc/wireguard
>-rw-r--r-- 1 root root  337 Oct 23 18:00 wg0.conf
>```
<!-- }}} -->

<!-- NetworkManager {{{-->
## NetworkManager

Manage **WireGuard** VPN connection with [NetworkManager](https://wiki.archlinux.org/title/NetworkManager#Usage)

> [!example]-
>
>```sh
># Import profile
>nmcli connection import type wireguard file /etc/wireguard/wg0.conf
>
># Enable/Disable connection
>nmcli connection up wg0
>nmcli connection down wg0
>
># Delete profile
>nmcli connection delete wg0
>nmcli device delete ipv6leakintrf0
>
># Prevent autoconnect
>nmcli connection modify wg0 connection.autoconnect no
>```

Disable IPv6

> [!example]-
>
> [Disable IPv6 with NetworkManager](https://wiki.archlinux.org/title/IPv6#NetworkManager_3)
>
>```sh
>nmcli connection modify wlp1s0 ipv6.method "disabled"
>```
> 
> Disable IPv6 in the interface's configuration file
>
>```sh
>/proc/sys/net/ipv6/conf/wlp1s0/disable_ipv6
>```
>```sh
>1
>```
>
<!-- }}} -->
