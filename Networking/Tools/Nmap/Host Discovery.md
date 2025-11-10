---
id: Host Discovery
aliases: []
tags:
  - Networking/Tools/Nmap/Host-Discovery
---

# Host Discovery

Host discovery on the network

___

<!-- ICMP Echo Request Scan {{{-->
## ICMP Echo Request Scan

<!-- Scan Network Range {{{-->
### Scan Network Range

Network ICMP discovery

```sh
nmap -PE -PP -PM -sn <network_range> -oA network_icmp_discovery
```

> [!info]-
>
> - `-sn`: Ping scan only (*no port scan*)
> - `-PE`: Send ICMP Echo Request
> - `-PP`: Send ICMP Timestamp Request
> - `-PM`: Send ICMP Netmask Request

List IPs with details

```sh
sudo nmap 10.129.2.0/24 -sn -oA network_icmp_scan
```

> [!info]-
>
> - `-sn`: Disable port scanning (send ARP ping)
> - `-oA`: Save scan results

```sh
sudo nmap 10.129.2.0/24 -sn -oA network_icmp_scan -PE
```

> [!info]-
>
> - `-sn`: Disable port scanning (send ARP ping)
> - `-oA`: Save scan results
> - `-PE`: Make sure ICMP packet is sent

```sh
sudo nmap 10.129.2.0/24 -sn -oA network_icmp_scan -PE --reason
```

> [!info]-
>
> - `-sn`: Disable port scanning (send ARP ping)
> - `-oA`: Save scan results
> - `-PE`: Make sure ICMP packet is sent
> - `--reason`: Display reason for the result

List IPs only

```sh
sudo nmap 10.129.2.0/24 -sn -oA network_icmp_scan | grep for | cut -d" " -f5
```

<!-- }}} -->

<!-- Scan Multiple IPs {{{-->
### Scan Multiple IPs

Scan multiple IP addresses

```sh
sudo nmap -sn -oA network_icmp_scan 10.129.2.18 10.129.2.19 10.129.2.20
```

<!-- }}} -->

<!-- Scan IP Range {{{-->
### Scan IP Range

Scan a range of IP addresses (`18-20`)

```sh
sudo nmap -sn -oA network_icmp_scan 10.129.2.18-20
```

<!-- }}} -->

<!-- Scan IP List {{{-->
### Scan IP List

Scan list of IPs

```sh
sudo nmap -sn -oA network_icmp_scan -iL hosts.txt
```

> [!info]-
>
> - `-sn`: Disable port scanning (send ARP ping)
> - `-oA`: Save scan results
> - `-iL`: Define a list of IPs

<!-- }}} -->

___
<!-- }}} -->
