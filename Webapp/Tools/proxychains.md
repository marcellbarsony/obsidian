---
id: proxychains
aliases: []
tags: []
---

# Proxychains

[proxychains](https://github.com/haad/proxychains)
is a tool that forces any TCP connection made by any given application
to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy.

Supported auth-types

- [SOCKS4/5](https://en.wikipedia.org/wiki/SOCKS): "user/pass"
- [HTTP](https://en.wikipedia.org/wiki/HTTP): "basic"

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/proxychains-ng/)

```sh
sudo apt install libproxychains4
```

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

Edit the configuration file

```sh
sudo vim /etc/proxychains4.conf
```

Add HTTP proxy

```sh
[ProxyList]
# add proxy here
# meanwhile
# defaults set to "tor"
# socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Execute a command through proxychains

```sh
proxychains -q <command>
```

<!-- Example {{{-->
> [!example]-
>
> [[cURL]]
>
> ```sh
> proxychains -q curl http://SERVER_IP:PORT
> ```
> ```sh
> <!DOCTYPE html>
> <html lang="en">
>
> <head>
>     <meta charset="UTF-8">
>     <title>Ping IP</title>
>     <link rel="stylesheet" href="./style.css">
> </head>
>
> ...SNIP...
>
> </html>
> ```
<!-- }}} -->

___
<!-- }}} -->

