---
id: dnscrypt-proxy
aliases: []
tags: []
---

# dnscrypt-proxy

[dnscrypt-proxy](https://wiki.archlinux.org/title/Dnscrypt-proxy)
is a DNS proxy client with support for the encrypted DNS protocols
[DNS over HTTPS](https://wiki.archlinux.org/title/Domain_name_resolution#Privacy_and_security)
and [DNSCrypt](https://dnscrypt.info/)

<!-- Installation {{{-->
## Installation

Install the
[dnscrypt-proxy](https://archlinux.org/packages/extra/x86_64/dnscrypt-proxy/)
package

<!-- Example {{{-->
> [!example]
>
> ```sh
> sudo pacman -S dnscrypt-proxy
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

1. Stop [[NetworkManager]] from overwriting `/etc/resolv.conf`

<!-- Example {{{-->
> [!example]-
>
> [[NetworkManager]] - [Unmanaged /etc/resolv.conf](https://wiki.archlinux.org/title/NetworkManager#Unmanaged_/etc/resolv.conf)
>
> ```sh
> /etc/NetworkManager/conf.d/dns.conf
> ```
> ```sh
> [main]
> dns=none
> systemd-resolved=false
> ```
<!-- }}} -->

2. Set `/etc/resolv.conf`

<!-- Example {{{-->
> [!example]-
>
> ```sh
> /etc/resolv.conf
> ```
> ```sh
>  # DNSCrypt
>  nameserver ::1
>  nameserver 127.0.0.1
>  options edns0
> ```
<!-- }}} -->

3. [Configure](https://wiki.archlinux.org/title/Dnscrypt-proxy#Configuration)
   DNSCrypt-proxy

<!-- Example {{{-->
> [!example]-
>
> ```sh
> /etc/dnscrypt-proxy/dnscrypt-proxy.toml
> ```
>
> Set server names
>
> ```sh
> server_names = ['NextDNS-<profile_id>']
> ```
>
> Set bootstrap resolvers
>
> ```sh
> bootstrap_resolvers = ['9.9.9.11:53', '1.1.1.1:53']
> ```
>
> Set [static entries](https://my.nextdns.io/<uid>/setup)
>
> ```sh
> [static]
> [static.'NextDNS-<profile_id>']
> stamp = 'sdns://<dsns_id>'
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Whitelist {{{-->
## Whitelist

### Domain

1. Whitelist the domain on
   [NextDNS's Allowlist](https://my.nextdns.io/<uid>/allowlist)

2. Whitelist the domain in `/etc/dnscrypt-proxy/allowed-names.txt`

3. Restart `dnscrypt-proxy.service`

<!-- Example {{{-->
> [!example]
>
> ```sh
> sudo systemctl restart dnscrypt-proxy.service
> ```
<!-- }}} -->

4. Restart `NetworkManager.service` (*optional*)

<!-- Example {{{-->
> [!example]
>
> ```sh
> sudo systemctl restart NetworkManager.service
> ```
<!-- }}} -->
___
<!-- }}} -->
