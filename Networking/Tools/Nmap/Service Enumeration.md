---
id: Service Enumeration
aliases: []
tags:
  - Networking/Tools/Nmap/Service-Enumeration
---

# Service Enumeration

___

<!-- Service Version Detection {{{-->
## Service Version Detection

Full Port Scan & Service Version Detection

```sh
sudo nmap $target -p- -sV [-Pn] [-n] [--disable-arp-ping] [--stats-every=5s]
```

<!-- Info {{{-->
> [!info]-
>
> - `-p-`: Scans all ports
> - `-sV`: Performs service version detection on specified ports
> - `-Pn`: Disable ICMP Echo requests
> - `-n`: Disable DNS resolution
> - `--disable-arp-ping`: Disable ARP ping
> - `--stats-every=5s`: Shows the progress of the scan every 5 seconds
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Show TCP ports with the corresponding services and their versions
>
> ```sh
> sudo nmap 10.129.2.28 -p- -sV
> ```
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 20:00 CEST
> Nmap scan report for 10.129.2.28
> Host is up (0.013s latency).
> Not shown: 65525 closed ports
> PORT      STATE    SERVICE      VERSION
> 22/tcp    open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
> 25/tcp    open     smtp         Postfix smtpd
> 80/tcp    open     http         Apache httpd 2.4.29 ((Ubuntu))
> 110/tcp   open     pop3         Dovecot pop3d
> 139/tcp   filtered netbios-ssn
> 143/tcp   open     imap         Dovecot imapd (Ubuntu)
> 445/tcp   filtered microsoft-ds
> 993/tcp   open     ssl/imap     Dovecot imapd (Ubuntu)
> 995/tcp   open     ssl/pop3     Dovecot pop3d
> MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
> Service Info: Host:  inlane; OS: Linux; CPE: cpe:/o:linux:linux_kernel
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 91.73 seconds
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Grab the banner of a service

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
<!-- }}} -->

<!-- Tcpdump {{{-->
### Tcpdump

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
