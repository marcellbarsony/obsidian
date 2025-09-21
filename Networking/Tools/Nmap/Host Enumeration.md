---
id: Host Enumeration
aliases: []
tags:
  - Networking/Tools/Nmap/Host-Enumeration
---

# Host Enumeration

Enumerate a host with known IP address

The information needed includes

- Open ports & services
- Service versions
- Information that the services provided
- Operating system

## TCP Scan

### Top 10 TCP Port Scan

Scan the most frequent TCP ports

```sh
sudo nmap <target_ip> --top-ports=10
```

Disable on closed ports:

- ICMP echo requests (`-Pn`)
- DNS resolution (`-n`)
- ARP ping scan (`--disable-arp-ping`).

Top 10 TCP Ports, ranked in the `nmap-services` file

| Port     | SERVICE       |
| -------- | ------------- |
| 21/tcp   | ftp           |
| 22/tcp   | ssh           |
| 23/tcp   | telnet        |
| 25/tcp   | smtp          |
| 80/tcp   | http          |
| 110/tcp  | pop3          |
| 139/tcp  | netbios-ssn   |
| 443/tcp  | https         |
| 445/tcp  | microsoft-ds  |
| 3389/tcp | ms-wbt-server |

### Open Port Discovery

Discover open ports on the target machine

```sh
nmap -sV --open -oA target_initial_scan <target_ip>
```

- `-sV`: Enable service/version detection
- `--open`: Scan open ports only
- `-oA`: Save output in all fomats

### Full Port Scan

Run a full port scan for services running on non-standard ports

```sh
nmap -p- --open -oA target_full_tcp_scan <target_ip>
```

- `-p-`: Scan all ports
- `--open`: Scan open ports only
- `-oA`: Save output in all fomats

### Script Scan

Run a script scan on discovered ports (e.g., 22, 80)

```sh
nmap -sC -p 22,80 -oA target_script_scan <target>
```

- `-sC`: Run default NSE scripts (auth, banner grabbing, vuln detection, etc.)
- `-p 20,80`: Scan specified ports only
- `-oA`: Save output in all fomats

### TCP Connect Scan

**TCP Connect Scan** (`-sT`) uses the three-way hansdhake to determine if a port
is open

```sh
sudo nmap <target_ip> -p 443
```

```sh
sudo nmap <target_ip> -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

## UDP Scan

Scan top 100 UDP ports

```sh
sudo nmap <target_ip> -sU -F
```

- `-sU`: Perform UDP scan
- `-F`: Scan top 100 ports

Scan specific UDP port

```sh
sudo nmap <target_ip> -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason
```

- `-sU`: UDP scan
- `-Pn`: Disable ICMP echo request
- `-n`: Disable DNS resolution
- `--disable-arp-ping`: Disable ARP ping
- `--packet-trace`: Show all packets sent and received
- `-p 137`: Scan specified port
- `--reason`: Display reason
