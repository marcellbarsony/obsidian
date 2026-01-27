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

Service Version Detection & Full Port Scan

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

<!-- Service Banner {{{-->
## Service Banner

Grab the banner of a service

```sh
sudo nmap -v $target --script banner.nse -oA nmap-script-banner
```

___
<!-- }}} -->
