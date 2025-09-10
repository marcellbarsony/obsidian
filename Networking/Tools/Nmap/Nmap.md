---
id: Nmap
aliases: []
tags:
  - Networking/Tools/Nmap
links: "[[Tools]]"
---

# Nmap

## Usage

Synopsis

```shell
nmap [Scan Type(s)] [Options] {target specification}
```

<!-- Basic scan {{{-->
### Basic scan

```sh
# IP address scan (TCP)
nmap {target_ip}
nmap {target_ip} --reason
nmap --open {target_ip}
nmap --packet-trace {target_ip}

# Script & Service scan
nmap -sC -sV {target_ip}

# TCP scan
nmap -sT {target_ip}
```
<!-- }}} -->

<!-- Banner grabbing {{{-->
### Banner grabbing

Grab the banner of a service

```sh
map -sV --script=banner <target>
```
<!-- }}} -->

<!-- Network scan {{{-->
### Network scan

```sh
nmap {target_ip}/{CIDR}

# Exclude address(es)
nmap {target_ip}/{CIDR} --exclude {ip_address}
nmap {target_ip}/{CIDR} --exclude {ip_list.txt}
```

Scan from list
```sh
nmap -iL {ip_list.txt}
{ip_list.txt} nmap
```
<!-- }}} -->

<!-- OS scan {{{-->
### OS scan

```sh
nmap {target_ip} -O
```
<!-- }}} -->

<!-- Ping scan {{{-->
### Ping scan

```sh
# ICMP ping scan
nmap -sP {target_ip}
nmap -sP {target_ip}/{CIDR}

# TCP ping scan
nmap -PS {target_ip}

# TCP ACK ping scan
nmap -PA {target_ip}

# UDP ping scan
nmap -PU [port] {target_ip}
```
<!-- }}} -->

<!-- Port scan {{{-->
### Port scan

```sh
# All ports
nmap -p- {target_ip}

# Specific ports
nmap -p {port1},{port2} {target_ip}

# Specific TCP/UDP ports
nmap -p T:{port1},U:{port2} {target_ip}

# Range of ports
nmap -p {port1}-{port2} {target_ip}

# All named ports
nmap -p "*" {target_ip}

# 100 most common ports
nmap -F {target_ip}

# x most common ports
nmap --top-ports {x} {target_ip}
```
</details>
<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

Specifying `-sC` will run the defined scripts against a target

```sh
# Synopsis
nmap --script <script name> -p<port> <host>

# Example
nmap --script voldemort-info -p- 10.10.10.10
```

Nmap scripts are located at `/usr/share/nmap/scripts/`

```sh
locate scripts/citrix

/usr/share/nmap/scripts/citrix-brute-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps.nse
/usr/share/nmap/scripts/citrix-enum-servers-xml.nse
/usr/share/nmap/scripts/citrix-enum-servers.nse
```
<!--}}}-->

## Resources

- [Nmap: the Network Mapper](https://nmap.org/)
- [Nmap - man](https://linux.die.net/man/1/nmap)
