---
id: Nmap
aliases: []
tags:
  - Networking/Tools/Nmap
links: "[[Networking/Tools/Tools]]"
---

# Nmap

- [Nmap: the Network Mapper](https://nmap.org/)
- [Nmap - man](https://linux.die.net/man/1/nmap)

- [Reddit - Good nmap scan commands?](https://www.reddit.com/r/hackthebox/comments/dft53d/good_nmap_scan_commands/)
- [Reddit - nmap -p- scans](https://www.reddit.com/r/hackthebox/comments/1aguh1o/nmap_p_scans/)
- [Reddit - Nmap Cheat Sheet (figured yall could use this) ](https://www.reddit.com/r/hackthebox/comments/egcxkc/nmap_cheat_sheet_figured_yall_could_use_this/)

___

<!-- Port States {{{-->
## Port States

| State               | Description                                                             |
| ------------------- | ----------------------------------------------------------------------- |
| **open**            | Connection (*TCP, UDP, SCTP*) established                               |
| **closed**          | Response with `RST` flag is returned                                    |
| **filtered**        | **Error** or **no response** is returned (*firewall/packet filter*)     |
| **unfiltered**      | TCP-ACK scan only: Port is accessible, state is unknown (*open/closed*) |
| **open/filtered**   | No response; Firewall may protect the port                              |
| **closed/filtered** | IP ID idle scan only: Port **closed or filtered by firewall**           |

___
<!-- }}} -->

## Usage

Synopsis

```shell
nmap [Scan Type(s)] [Options] {target specification}
```

<!-- Basic scan {{{-->
### Basic scan


IP address scan (*TCP*)

```sh
nmap <target_ip>
```

```sh
nmap <target_ip> --reason
```

```sh
nmap --open <target_ip>
```

```sh
nmap --packet-trace <target_ip>
```

Script & Service scan

```sh
nmap -sC -sV <target_ip>
```

TCP scan

```sh
nmap -sT <target_ip>
```

___
<!-- }}} -->

<!-- Banner grabbing {{{-->
### Banner grabbing

Grab the banner of a service

```sh
nmap -sV --script=banner <target_ip> -oA script-banner
```

___
<!-- }}} -->

<!-- Network scan {{{-->
### Network scan

```sh
nmap <target_ip>/<CIDR>
```

Exclude address(es)

```sh
nmap <target_ip>/<CIDR> --exclude <target_ip>
```

```sh2
nmap <target_ip>/<CIDR> --exclude <ip_list.txt>
```

Scan from list

```sh
nmap -iL <ip_list.txt>
```

```sh
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

ICMP ping scan

```sh
nmap -sP <target_ip> -oA icmp-ping-scan
```

```sh
nmap -sP <target_ip>/<cidr> -oA icmp-ping-scan
```

TCP ping scan

```sh
nmap -PS <target_ip> -oA tcp_ping_scan
```

TCP ACK ping scan

```sh
nmap -PA <target_ip> -oA tcp_ack_scan
```

UDP ping scan

```sh
nmap -PU [port] <target_ip> -oA udp-ping-scan
```
<!-- }}} -->

<!-- Port scan {{{-->
### Port scan

All ports

```sh
nmap -p- <target_ip>
```

Specific ports

```sh
nmap -p <port1>,<port2> <target_ip>
```

Specific TCP/UDP ports

```sh
nmap -p T:<port1>,U:<port2> <target_ip>
```

Range of ports

```sh
nmap -p <port1>-<port2> <target_ip>
```

All named ports

```sh
nmap -p "*" <target_ip>
```

100 most common ports

```sh
nmap -F <target_ip>
```

x most common ports

```sh
nmap --top-ports <x> <target_ip>
```

___
<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

Specifying `-sC` will run the defined scripts against a target

Synopsis

```sh
nmap --script <script name> -p<port> <host>
```

> [!example]-
>
> ```
> nmap --script voldemort-info -p- 10.10.10.10
> ```

Nmap scripts are located at `/usr/share/nmap/scripts/`

> [!example]-
>
> ```sh
> locate scripts/citrix
> ```
> ```sh
> /usr/share/nmap/scripts/citrix-brute-xml.nse
> /usr/share/nmap/scripts/citrix-enum-apps-xml.nse
> /usr/share/nmap/scripts/citrix-enum-apps.nse
> /usr/share/nmap/scripts/citrix-enum-servers-xml.nse
> /usr/share/nmap/scripts/citrix-enum-servers.nse
> ```

___
<!--}}}-->

<!-- Options {{{-->
## Options

Save output in all formats (normal, XML, and grepable)

```sh
nmap -sV --open -oA nibbles_initial_scan <target_ip>
```

> [!info]-
>
> - Normal: `nibbles_initial_scan.nmap`
> - XML: `nibbles_initial_scan.xml`
> - Grepable: `nibbles_initial_scan.gnmap`

Display statistics every 5 seconds

```sh
--stats-every=5s
```

Check which ports are scanned for a given scan type

```sh
nmap -v -oG -
```

___
<!-- }}} -->

<!-- Output Formats {{{-->
## Output Formats

**Nmap** can save the output in 3 different formats:

- `-oN`: Normal output - `.nmap` extension
- `-oG`: Grepable output - `.gnmap` extension
- `-oX`: XML output - `.xml` extension

`-oA` saves the reusult in all formats

### HTML Reports

Convert `.xml` to HTML reports with [xsltproc](https://linux.die.net/man/1/xsltproc)

```sh
xsltproc target.xml -o target.html
```

___
<!-- }}} -->
