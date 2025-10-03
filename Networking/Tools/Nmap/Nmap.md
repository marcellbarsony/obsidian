---
id: Nmap
aliases: []
tags:
  - Networking/Tools/Nmap
links: "[[Tools]]"
---

# Nmap

- [Nmap: the Network Mapper](https://nmap.org/)
- [Nmap - man](https://linux.die.net/man/1/nmap)

- [Reddit - Good nmap scan commands?](https://www.reddit.com/r/hackthebox/comments/dft53d/good_nmap_scan_commands/)
- [Reddit - nmap -p- scans](https://www.reddit.com/r/hackthebox/comments/1aguh1o/nmap_p_scans/)
- [Reddit - Nmap Cheat Sheet (figured yall could use this) ](https://www.reddit.com/r/hackthebox/comments/egcxkc/nmap_cheat_sheet_figured_yall_could_use_this/)

## Usage

Synopsis

```shell
nmap [Scan Type(s)] [Options] {target specification}
```

<!-- Basic scan {{{-->
### Basic scan

```sh
# IP address scan (TCP)
nmap <target_ip>
nmap <target_ip> --reason
nmap --open <target_ip>
nmap --packet-trace <target_ip>

# Script & Service scan
nmap -sC -sV <target_ip>

# TCP scan
nmap -sT <target_ip>
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
nmap <target_ip>/<CIDR>

# Exclude address(es)
nmap <target_ip>/<CIDR> --exclude <target_ip>
nmap <target_ip>/<CIDR> --exclude <ip_list.txt>
```

Scan from list
```sh
nmap -iL <ip_list.txt>
<ip_list.txt> nmap
```
<!-- }}} -->

<!-- OS scan {{{-->
### OS scan

```sh
nmap <target_ip> -O
```
<!-- }}} -->

<!-- Ping scan {{{-->
### Ping scan

```sh
# ICMP ping scan
nmap -sP <target_ip>
nmap -sP <target_ip>/{CIDR}

# TCP ping scan
nmap -PS <target_ip>

# TCP ACK ping scan
nmap -PA <target_ip>

# UDP ping scan
nmap -PU [port] <target_ip>
```
<!-- }}} -->

<!-- Port scan {{{-->
### Port scan

```sh
# All ports
nmap -p- <target_ip>

# Specific ports
nmap -p <port1>,<port2> <target_ip>

# Specific TCP/UDP ports
nmap -p T:<port1>,U:<port2> <target_ip>

# Range of ports
nmap -p <port1>-<port2> <target_ip>

# All named ports
nmap -p "*" <target_ip>

# 100 most common ports
nmap -F <target_ip>

# x most common ports
nmap --top-ports <x> <target_ip>
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

> [!example]-
>
>```sh
>locate scripts/citrix
>
>/usr/share/nmap/scripts/citrix-brute-xml.nse
>/usr/share/nmap/scripts/citrix-enum-apps-xml.nse
>/usr/share/nmap/scripts/citrix-enum-apps.nse
>/usr/share/nmap/scripts/citrix-enum-servers-xml.nse
>/usr/share/nmap/scripts/citrix-enum-servers.nse
>```
<!--}}}-->

<!-- Options {{{-->
## Options

### Save Output

Output in all formats (normal, XML, and grepable)

```sh
nmap -sV --open -oA nibbles_initial_scan <target_ip>
```

- Normal: `nibbles_initial_scan.nmap`
- XML: `nibbles_initial_scan.xml`
- Grepable: `nibbles_initial_scan.gnmap`

### Display Stats

Automatically display statistics every 5 seconds

```sh
--stats-every=5s
```

### Check Scan Type Options

Check which ports are scanned for a given scan type

```sh
nmap -v -oG -
```
<!-- }}} -->

<!-- Port States {{{-->
## Port States

| State               | Description                                                           |
| ------------------- | --------------------------------------------------------------------- |
| **open**            | Connection (TCP, UDP, SCTP) established                               |
| **closed**          | Response with `RST` flag is returned                                  |
| **filtered**        | **Error** or **no response** is returned                              |
| **unfiltered**      | TCP-ACK scan only: Port is accessible, state is unknown (open/closed) |
| **open/filtered**   | No response; Firewall may protect the port                            |
| **closed/filtered** | IP ID idle scan only: Port **closed or filtered by firewall**         |
<!-- }}} -->

<!-- Output Formats {{{-->
## Output Formats

**Nmap** can save the output in 3 different formats:

- `-oN`: Normal output - `.nmap` extension
- `-oG`: Grepable output - `.gnmap` extension
- `-oX`: XML output - `.xml` extension

`-oA` saves the reust in all formats

### HTML Reports

Convert `.xml` to HTML reports with [xsltproc](https://linux.die.net/man/1/xsltproc)

```sh
xsltproc target.xml -o target.html
```
<!-- }}} -->
