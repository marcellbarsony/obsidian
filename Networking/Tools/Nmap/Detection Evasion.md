---
id: Detection Evasion
aliases: ["Firewall and IDS/IPS Evasion"]
tags:
  - Networking/Tools/Nmap/Detection-Evasion
---

# Detection Evasion

___

<!-- Firewall {{{-->
## Firewall

A [[Firewalls/General|Firewall]] is a device applying a security measure
against unauthorized connection attempts from external networks

<!-- Detection {{{-->
### Detection

An effective technique to
[Determine Firewall rules](https://nmap.org/book/determining-firewall-rules.html)
is to

1. Start with a normal [[#SYN Scan]]
2. Move on to more exotic techniques
   (*e.g., [[#ACK Scan]], [[#UDP Scan]], IP ID sequencing, etc.*)

Systems are required (*[RFC 793](https://www.rfc-editor.org/rfc/rfc793.txt)*)
to send negative response (*TCP RST packet*) to unexpected connection requests.

Filtering devices, on the other hand, tend to drop packets destined
for disallowed ports. In some cases they send ICMP error messages
(*usually `Port Unreachable`*) instead.

<!-- Info {{{-->
> [!info]- ICMP Error Messages
>
> - Net Unreachable
> - Net Prohibited
> - Host Unreachable
> - Host Prohibited
> - Port Unreachable
> - Proto Unreachable
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Detection of [[Nmap#Port States|closed]] and
> [[Nmap#Port States|filtered]] TCP ports
>
> ```sh
> nmap -sS -T4 scanme.nmap.org
> ```
> ```sh
> Starting Nmap ( https://nmap.org )
> Nmap scan report for scanme.nmap.org (64.13.134.52)
> Not shown: 994 filtered ports
> PORT    STATE  SERVICE
> 22/tcp  open   ssh
> 25/tcp  closed smtp
> 53/tcp  open   domain
> 70/tcp  closed gopher
> 80/tcp  open   http
> 113/tcp closed auth
>
> Nmap done: 1 IP address (1 host up) scanned in 5.40 seconds
> ```
>
> The host has a deny-by-default firewall policy
> (*`Not shown: 994 filtered ports`*)
<!-- }}} -->

<!-- SYN Scan {{{-->
#### SYN Scan

SYN Port Scan (*Full Connect Scan*)

```sh
sudo nmap -sS <target> [options] -Pn -n --disable-arp-ping -oA scan-tcp-syn
```

<!-- Info {{{-->
> [!info]-
>
> - `-sS`: Performs SYN scan on specified ports
> - `-Pn`: Disable ICMP Echo request
> - `-n`: Disable DNS Resolution
> - `--disable-arp-ping`: Disable ARP ping
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping
> ```
>
> ```sh
> PORT   STATE    SERVICE
> 21/tcp filtered ftp
> 22/tcp open     ssh
> 25/tcp filtered smtp
> ```
>
> - `21/tcp filtered`: Likely blocked by a firewall
> - `25/tcp filtered`: Likely blocked by a firewall
> - `22/tcp open`: Passed through the firewall or directly reachable
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Fingerprint {{{-->
### Fingerprint

[Firewalking](https://en.wikipedia.org/wiki/Firewalk_(computing))
is an active technique that utilizes
[traceroute](https://en.wikipedia.org/wiki/Traceroute) techniques and
[TTL](https://en.wikipedia.org/wiki/Time_to_live) values
determine firewall rules and gateway ACL filters.

Nmap [firewalk](https://nmap.org/nsedoc/scripts/firewalk.html) script

```sh
nmap <target> --script firewalk -oA script-firewalk
```

<!-- Warning {{{-->
> [!warning]
>
> Expect mixed results: most modern firewalls don't expose enough behavior
> for clear identification
<!-- }}} -->

<!-- }}} -->

<!-- Evasion {{{-->
### Evasion

Systems are required (*[RFC 793](https://www.rfc-editor.org/rfc/rfc793.txt)*)
to send negative response (*TCP RST packet*) to unexpected connection requests.

Filtering devices, on the other hand, tend to drop packets destined
for disallowed ports. In some cases they send ICMP error messages
(*usually `Port Unreachable`*) instead.

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sA -T4 scanme.nmap.org
> ```
> ```sh
> Starting Nmap ( https://nmap.org )
> Nmap scan report for scanme.nmap.org (64.13.134.52)
> Not shown: 994 filtered ports
> PORT    STATE      SERVICE
> 22/tcp  unfiltered ssh
> 25/tcp  unfiltered smtp
> 53/tcp  unfiltered domain
> 70/tcp  unfiltered gopher
> 80/tcp  unfiltered http
> 113/tcp unfiltered auth
>
> Nmap done: 1 IP address (1 host up) scanned in 5.96 seconds
> ```
>
> This website only accepts packets that are part of or related to
> an established connection.
>
> Unsolicited `ACK` packets are dropped,
> except to the six special ports shown.
>
> Special rules allow all packets to the ports `22`, `25`, `53`, `70`,
> and `80`, as well as sending a `RST` packet in response to port `113`
> probes.
>
> The six shown ports are in the [[Nmap#Port States|unfiltered]] state,
> since the `ACK` scan cannot further divide them into
> [[Nmap#Port States|open]] (`22`, `53`, and `80`) or
> [[Nmap#Port States|closed]] (`25`, `70`, `113`).
<!-- }}} -->

<!-- ACK Scan {{{-->
#### ACK Scan

Firewalls and IPS/IDS systems detect **TCP ACK** (*`-sA`*) scans
harder than **SYN** (*`-sS`*) or **TCP Connect** (*`-sT`*) scans:

- The **TCP ACK** scan sends a TCP packet with with only
  the `ACK` flag set
- The **firewall cannot determine** whether the packet is a part
  of an ongoing conversation
  (*established from an external or internal network*)
- The **receiving host must respond** with a `RST` flag
  whether the port is closed or open

```sh
sudo nmap -sA <target> [options] -Pn -n --disable-arp-ping -oA scan-ack
```

<!-- Info {{{-->
> [!info]-
>
> - `-sA`: Performs `ACK` scan on specified ports
> - `-Pn`: Disable ICMP Echo request
> - `-n`: Disable DNS Resolution
> - `--disable-arp-ping`: Disable ARP ping
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping
> ```
>
> ```sh
> PORT   STATE      SERVICE
> 21/tcp filtered   ftp
> 22/tcp unfiltered ssh
> 25/tcp filtered   smtp
> ```
>
> Port `21` and `25` are [[Nmap#Port States|filtered]]
> (*returning **ICMP Port Unreachable** or **no response**,
> meaning the packets are dropped (most likely by a firewall)*)
<!-- }}} -->

<!-- }}} -->

<!-- UDP Scan {{{-->
#### UDP Scan

Many UDP applications will simply ignore unexpected packets,
leaving Nmap unsure whether the port is in
[[Nmap#Port States|open]] or [[Nmap#Port States|filtered]] state.

```sh
sudo nmap -sU <target> [options] -Pn -n --disable-arp-ping -oA scan-udp
```

<!-- Info {{{-->
> [!info]-
>
> - `-sU`: UDP Scan
> - `-Pn`: Disable ICMP Echo request
> - `-n`: Disable DNS Resolution
> - `--disable-arp-ping`: Disable ARP ping
<!-- }}} -->

> [!tip]
>
> Send different UDP probes (*e.g., `-sC`, `-sV`, etc.*)
> in a hope of eliciting a response

<!-- Example {{{-->
> [!example]-
>
> UDP scan against firewalled host
>
> ```sh
> nmap -sU -p50-59 scanme.nmap.org
> ```
> ```
> Starting Nmap ( https://nmap.org )
> Nmap scan report for scanme.nmap.org (64.13.134.52)
> PORT   STATE         SERVICE
> 50/udp open|filtered re-mail-ck
> 51/udp open|filtered la-maint
> 52/udp open|filtered xns-time
> 53/udp open|filtered domain
> 54/udp open|filtered xns-ch
> 55/udp open|filtered isi-gl
> 56/udp open|filtered xns-auth
> 57/udp open|filtered priv-term
> 58/udp open|filtered xns-mail
> 59/udp open|filtered priv-file
>
> Nmap done: 1 IP address (1 host up) scanned in 1.38 seconds
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- IPS/IDS {{{-->
## IPS/IDS

IDS/IPS systems are passive traffic monitoring systems
examining all connections between hosts.

Several Virtual Private Servers (`VPS`) with different IPs
are recommended to determine whether an **IPS/IDS** is in place:
scanning a single port aggressively may trigger **IDS/IPS**
and block the IP of the VPS.

<!-- Detection {{{-->
### Detection

An IDS/IPS may be in the path if

- Probes get dropped silently (*no reply*) or unexpected `RST`/`ICMP`s
  are coming from the gateway
- One source IP gets blocked after a burst but other IPs do not
- If responses change depending on a probe rate, payload or fragmentation

<!-- }}} -->

<!-- Evasion {{{-->
### Evasion

<!-- Decoys {{{-->
#### Decoys

Generates various random IP addresses to disguise the origin of the packet sent.
The decoy addresses must be:
- On the same subnet
- Alive on the network

```sh
sudo nmap <target> [-p <port>] -Pn -n --disable-arp-ping -D RND:5
```

<!-- Info {{{-->
> [!info]-
>
> - `-Pn`: Disable ICMP Echo requests
> - `-n`: Disable DNS resolution
> - `--disable-arp-ping`: Disable ARP ping
> - `-D RND:5`: Generate 5 random IP addresses, indicating the decoy source IP
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
> ```
>
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 16:14 CEST
> SENT (0.0378s) TCP 102.52.161.59:59289 > 10.129.2.28:80 S ttl=42 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> SENT (0.0378s) TCP 10.10.14.2:59289 > 10.129.2.28:80 S ttl=59 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> SENT (0.0379s) TCP 210.120.38.29:59289 > 10.129.2.28:80 S ttl=37 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> SENT (0.0379s) TCP 191.6.64.171:59289 > 10.129.2.28:80 S ttl=38 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> SENT (0.0379s) TCP 184.178.194.209:59289 > 10.129.2.28:80 S ttl=39 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> SENT (0.0379s) TCP 43.21.121.33:59289 > 10.129.2.28:80 S ttl=55 id=29822 iplen=44  seq=3687542010 win=1024 <mss 1460>
> RCVD (0.1370s) TCP 10.129.2.28:80 > 10.10.14.2:59289 SA ttl=64 id=0 iplen=44  seq=4056111701 win=64240 <mss 1460>
> Nmap scan report for 10.129.2.28
> Host is up (0.099s latency).
>
> PORT   STATE SERVICE
> 80/tcp open  http
> MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
>
> Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
> ```
<!-- }}} -->



<!-- }}} -->

<!-- Testing Firewall Rules {{{-->
#### Testing Firewall Rules

Test if the traffic to port `445/tcp` is [[Nmap#Port States|allowed]],
[[Nmap#Port States|blocked]], or [[Nmap#Port States|filtered]]

```sh
sudo nmap 10.129.2.28 -n -Pn -p445 -O
```
<!-- }}} -->

<!-- Different Source IP {{{-->
#### Different Source IP

Scan by using a different source IP

```sh
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

> [!info]-
>
> - `-O`: Enable OS detection
> - `-S`: Define different source IP
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- DNS Proxying {{{-->
## DNS Proxying

By default, a reverse DNS resolution is performed (*over port `UDP/53`*)
unless otherwise specified to find more information about the target.

Specifying the DNS server (`--dns-server <ns>,<ns>`) could be fundamental
in a demilitarized zone (DMZ) as a company's DNS servers
are usually more trusted than those from the internet.

<!-- Info {{{-->
> [!info]- DNS Query Port
>
> DNS queries are made over port `UDP/53`.
>
> This is changing due to [[IPv6]] and DNSSEC expansions,
> causing DNS requests to be made via port `TCP/53`.
>
> Port `TCP/53` was previously only used for
> [[DNS/General#DNS Zone Transfer|DNS Zone Transfer]]
> or data transfer larger than 512 bytes.
<!-- }}} -->

Reference `SYN` scan against a [[Nmap#Port States|filtered]] port

```sh
sudo nmap <target> [-p <port>] -sS -Pn -n --disable-arp-ping
```

<!-- Info {{{-->
> [!info]-
>
> - `-sS`: Performs SYN scan on specified ports
> - `-Pn`: Disable ICMP Echo requests
> - `-n`: Disable DNS resolution
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> SYN-Scan of a [[Nmap#Port States|filtered]] port
>
> ```sh
> sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace
> ```
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-21 22:50 CEST
> SENT (0.0417s) TCP 10.10.14.2:33436 > 10.129.2.28:50000 S ttl=41 id=21939 iplen=44  seq=736533153 win=1024 <mss 1460>
> SENT (1.0481s) TCP 10.10.14.2:33437 > 10.129.2.28:50000 S ttl=46 id=6446 iplen=44  seq=736598688 win=1024 <mss 1460>
> Nmap scan report for 10.129.2.28
> Host is up.
>
> PORT      STATE    SERVICE
> 50000/tcp filtered ibm-db2
>
> Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
> ```
>
> The firewall accepts TCP port `53` and it's likely that IDS/IPS filters
> might be configured weakly.
<!-- }}} -->

<!-- Scan From DNS Port {{{-->
### Scan From DNS Port

Perform a scan (*e.g., `SYN` scan*) against a target port via DNS proxy
(*port `53`*)

```sh
sudo nmap <target> [-p <port>] [-sS] -Pn -n --disable-arp-ping --source-port 53
```

<!-- Info {{{-->
> [!info]-
>
> - `-sS`: Performs SYN scan on specified ports
> - `-Pn`: Disable ICMP Echo requests
> - `-n`: Disable DNS resolution
> - `--source-port 53`: Specify scan source port
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> SYN Scan from DNS port
>
> ```sh
> sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
> ```
>
> ```sh
> SENT (0.0482s) TCP 10.10.14.2:53 > 10.129.2.28:50000 S ttl=58 id=27470 iplen=44  seq=4003923435 win=1024 <mss 1460>
> RCVD (0.0608s) TCP 10.129.2.28:50000 > 10.10.14.2:53 SA ttl=64 id=0 iplen=44  seq=540635485 win=64240 <mss 1460>
> Nmap scan report for 10.129.2.28
> Host is up (0.013s latency).
>
> PORT      STATE SERVICE
> 50000/tcp open  ibm-db2
> MAC Address: DE:AD:00:00:BE:EF (Intel Corporate)
>
> Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
> ```
<!-- }}} -->

In case of [[Nmap#Port States|open]] port, try to establish connection

```sh
ncat -nv <target> <port> --source-port 53
```

<!-- Example {{{-->
> [!example]-
>
> Connect to the [[Nmap#Port States|filtered]] port
>
> ```sh
> ncat -nv --source-port 53 10.129.2.28 50000
> ```
> ```sh
> Ncat: Version 7.80 ( https://nmap.org/ncat )
> Ncat: Connected to 10.129.2.28:50000.
> 220 ProFTPd
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
