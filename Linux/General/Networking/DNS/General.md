---
id: DNS
aliases: []
tags:
  - Linux/General/Networking/DNS
---

# DNS (Linux)

- [Arch Wiki - DNS Resolution](https://wiki.archlinux.org/title/Domain_name_resolution)
- [Arch Wiki - Openresolv](https://wiki.archlinux.org/title/Openresolv)

___

<!-- DNS Resolution {{{-->
## DNS Resolution

The glibc resolver reads `/etc/resolv.conf`

___
<!-- }}} -->

<!-- Tools {{{-->
## DNS Tools

### NetworkManager

Stop NetworkManager from modifying `/etc/resolv.conf`

> [!example]-
>
> [Unmanaged /etc/resolv.conf](https://wiki.archlinux.org/title/NetworkManager#Unmanaged_/etc/resolv.conf)
> ```sh
> /etc/NetworkManager/conf.d/dns.conf
> ```
>
> ```sh
> [main]
> dns=none
> ```

### Bind9

- [GitHub - Bind9](https://github.com/isc-projects/bind9)
- [Arch Wiki - BIND](https://wiki.archlinux.org/title/BIND)

### ldns

- [GitHub - ldns](https://github.com/NLnetLabs/ldns)

___
<!-- }}} -->

<!-- Service {{{-->
## Service

Manage the `systemd-resolved` service

```sh
stemctl status systemd-resolved.service
```

Start the service

```sh
stemctl start systemd-resolved.service
```

Stop the service

```sh
stemctl stop systemd-resolved.service
```

Config

```sh
systemd_resolved_service = "sudo systemctl start systemd-resolved.service"
```

___
<!-- }}} -->

<!-- Cache {{{-->
## Cache

Flush [systemd-resolved](https://wiki.archlinux.org/title/Systemd-resolved) DNS
cache

```sh
sudo systemd-resolve --flush-caches
```

Flush browser DNS cache

> [!info]-
>
> Firefox
>
> ```md
> about:networking#dns
> ```
>
> Chromium
>
> ```
> chrome://net-internals/#dns
> ```

___
<!-- }}} -->

<!-- Security {{{-->
## Security

[DNSSEC](https://wiki.archlinux.org/title/DNSSEC)

> [!todo]

___
<!-- }}} -->

<!-- DNS Leaks {{{-->
## DNS Leaks

### Disable IPv6

- [Arch Wiki - IPv6: Disable_IPv6](https://wiki.archlinux.org/title/IPv6#Disable_IPv6)
- [Arch Wiki - IPv6: NetworkManager](https://wiki.archlinux.org/title/IPv6#NetworkManager)

#### NetworkManager

Disable IPv6 via NetworkManager

```sh
nmcli connection modify <connection_name> ipv6.method "disabled"
```

#### ProtonVPN

[ProtonVPN - Prevent IPv6 VPN Leaks](https://protonvpn.com/support/prevent-ipv6-vpn-leaks/)

IPv6 traffic is disabled; any potential IPv6 traffic is routed to null route
to ensure the device cannot make connections over IPv6.

### WebRTC

- [BrowserLeaks - WebRTC](https://browserleaks.com/webrtc)

#### Firefox

Disable WebRTC in Firefox
(`/* 7020: disable WebRTC (Web Real-Time Communication`)

```json
media.peerconnection.enabled=false;
```

#### Chrome

- [Chrome Store - WebRTC Network Limiter](https://chrome.google.com/webstore/detail/webrtc-network-limiter/npeicpdbkakmehahjeeohfdhnlpdklia)

___
<!-- }}}-->
