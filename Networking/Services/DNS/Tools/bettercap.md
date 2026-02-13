---
id: bettercap
aliases: []
tags:
  - Networking/Services/DNS/Tools/bettercap
links: "[[Webapp/Enumeration/General|General]]"
---

# bettercap

[bettercap](https://www.bettercap.org/)
is the Swiss Army knife for WiFi, Bluetooth Low Energy,
wireless HID hijacking, CAN-bus and IPv4 and IPv6 networks
reconnaissance and MITM attacks

<!-- Info {{{-->
> [!info]- Resources
>
> [Hackviser](https://hackviser.com/tactics/tools/bettercap)
>
<!-- }}} -->

<!-- Resources {{{-->
> [!info]- Features
>
> - Network Sniffing
> - Man-in-the-Middle Attacks
> - Packet Manipulation
> - Session Hijacking
> - Credential Harvesting
> - Network Scanning
> - Vulnerability Scanning
> - DNS Spoofing
> - HTTPS Proxying
> - Packet Injection
>
<!-- }}} -->

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/bettercap/)

```sh
sudo apt install bettercap
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

**Help and Usage Information**

```sh
bettercap -h
```

**Start Bettercap**

Open the interactive console of Bettercap,
which enables users to interface with it from the command line
to perform various tasks regarding a network

```sh
bettercap
```

**Set Target**

Set the IP address or range to be the target of the attack.
Targeting makes it possible for the user to define the scope users operations,
letting Bettercap focus on the targeted source

```sh
set target <IP>
```

**Start Sniffer**

Start packet sniffing on the given network interface

```sh
net.sniff on
```

**Start ARP Spoofing**

Perform a man-in-the-middle attack with ARP spoofing enabled
which against the target and the gateway,
intercepting and manipulating their communications by deception of both sides

```sh
arp.spoof on
```

**Capture HTTP Traffic**

Listen HTTP traffic, allowing unencrypted request (*HTTP*) and response traffic
to pass through and be seen by the tool user for analysis.

```sh
http.proxy on
```

**Inject JavaScript**

Allow the user to injects JavaScript into the HTTP responses,
which could be used in testing the security of client-side applications.
It enables the user to assess how well defenses work exactly
when attacks are simulated against Cross-Site Scripting.

```sh
http.inject <script.js>
```

**Deauthenticate Wi-Fi Clients**

Deauthenticate clients from a specified Wi-Fi network—clients
are made to disconnect and then auto-reconnect.
The processes result in capturing the handshake packets ready for further operations.

```sh
wifi.deauth <target_MAC> -a <BSSID>
```

**View Network Interfaces**

List all the available network interfaces on the system

```sh
net.show
```

**Stop Bettercap**

This command exits the Bettercap console, stopping every active operation

```sh
exit
```

___
<!-- }}} -->
