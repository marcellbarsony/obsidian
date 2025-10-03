---
id: Detection Evasion
aliases: ["Firewall and IDS/IPS Evasion"]
tags: []
---

# Detection Evasion

<!-- Firewall {{{-->

## Firewalls

### ACK Scan

Firewalls and IPS/IDS systems detect **TCP ACK** scans (`-sA`) harder than
**SYN** (`-sS`) or **TCP Connect** scans (`-sT`):<br>
- **TCP ACK** sends a TCP packet with with only the `ACK` flag set
- The **firewall cannot determine** whether the packet is a part of an ongoing
  conversation (*established from an external or internal network*)
- The **receiving host must respond** with a `RST` flag whether the port is
  closed or open

SYN Scan (Full Connect Scan)

```sh
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping
```

> [!example]-
>
>```sh
>PORT   STATE    SERVICE
>21/tcp filtered ftp
>22/tcp open     ssh
>25/tcp filtered smtp
>```

ACK Scan

```sh
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping
```

> [!example]-
>
>```sh
>PORT   STATE      SERVICE
>21/tcp filtered   ftp
>22/tcp unfiltered ssh
>25/tcp filtered   smtp
>```

Port `21` and `25` are [[Nmap#Port States|filtered]] (returning **ICMP Port
Unreachable** or **no response**, meaning the packets are dropped (most likely
by a firewall).
<!-- }}} -->

<!-- IPS/IDS {{{-->
## IPS/IDS

Several Virtual Private Servers (`VPS`) with different IPs are recommended to
determine whether an IPS/IDS is in place: scanning a single port aggressively
may trigger IDS/IPS and block the IP of the VPS.

### Decoys

Generates various random IP adresses to disguise the origin of the packet sent.
The decoy addresses must be:
- Be on the same subnet
- Alive on the network

```sh
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

> [!info]-
>
> - `-D RND:5`: Generate 5 random IP addresses, indicating the decoy source IP

### Testing Firewall Rules

Test if the traffic to port `445/tcp` is [[Nmap#Port States|allowed]],
[[Nmap#Port States|blocked]], or [[Nmap#Port States|filtered]].

```sh
sudo nmap 10.129.2.28 -n -Pn -p445 -O
```

### Different Source IP

Scan by using a different source IP

```sh
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

> [!info]-
>
> - `-O`: Enable OS detection
> - `-S`: Define different source IP
<!-- }}} -->

## DNS Proxying

> [!todo]
>
> DNS Proxying
