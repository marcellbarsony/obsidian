---
id: Host Enumeration
aliases: []
tags:
  - Networking/Tools/Nmap/Host-Enumeration
---

# Host Enumeration

Enumerate a host with known IP address for

- Operating System Version
- Open Ports & Services
- Service Versions & Additional Information

___

<!-- OS Detection {{{-->
## OS Detection

<!-- Basic Scan {{{-->
### Basic Scan

Basic OS detection scan

```sh
sudo nmap -O $target -v [-Pn] -oA os-detection
```

<!-- Info {{{-->
> [!info]-
>
> - `-O`: OS detection
> - `-v`: Include device type (*e.g., router, firewall, etc.*),
>   OS family (*e.g., Linux*) and OS generation (*e.g., `2.6.X`*)
> - `-Pn`: Disable ping probes (*optional*)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -O -v scanme.nmap.org
> ```
> ```sh
> Starting Nmap ( https://nmap.org )
> Nmap scan report for scanme.nmap.org (74.207.244.221)
> Not shown: 994 closed ports
> PORT      STATE    SERVICE
> 22/tcp    open     ssh
> 80/tcp    open     http
> 646/tcp   filtered ldp
> 1720/tcp  filtered H.323/Q.931
> 9929/tcp  open     nping-echo
> 31337/tcp open     Elite
> Device type: general purpose
> Running: Linux 2.6.X
> OS CPE: cpe:/o:linux:linux_kernel:2.6.39
> OS details: Linux 2.6.39
> Uptime guess: 1.674 days (since Fri Sep  9 12:03:04 2011)
> Network Distance: 10 hops
> TCP Sequence Prediction: Difficulty=205 (Good luck!)
> IP ID Sequence Generation: All zeros
>
> Read data files from: /usr/local/bin/../share/nmap
> Nmap done: 1 IP address (1 host up) scanned in 5.58 seconds
>            Raw packets sent: 1063 (47.432KB) | Rcvd: 1031 (41.664KB)
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Version Scan {{{-->
### Version Scan

```sh
nmap -sV -O $target -oA os-detection-version -v
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -sV -O -v 129.128.X.XX
> ```
> ```sh
> Starting Nmap ( https://nmap.org )
> Nmap scan report for [hostname] (129.128.X.XX)
> Not shown: 994 closed ports
> PORT      STATE    SERVICE      VERSION
> 21/tcp    open     ftp          HP-UX 10.x ftpd 4.1
> 22/tcp    open     ssh          OpenSSH 3.7.1p1 (protocol 1.99)
> 111/tcp   open     rpc
> 445/tcp   filtered microsoft-ds
> 1526/tcp  open     oracle-tns   Oracle TNS Listener
> 32775/tcp open     rpc
> No exact OS matches for host
> TCP Sequence Prediction: Class=truly random
>                          Difficulty=9999999 (Good luck!)
> IP ID Sequence Generation: Incremental
> Service Info: OS: HP-UX
> ```
<!-- }}} -->

<!-- }}} -->

<!-- SYN Scan {{{-->
### SYN Scan

OS Detection & SYN Scan

```sh
nmap -sS -O $target -oA os-detection-syn -v
```

<!-- }}} -->

<!-- Aggressive Scan {{{-->
### Aggressive Scan

Aggressive Service Detection
(*includes `-sC`, `-sV` and `-O`*)

<!-- Warning {{{-->
> [!warning]
>
> Might be blocked by firewall
<!-- }}} -->

```sh
nmap -A $target -oA os-detection-aggressive -v
```

```sh
nmap -A $target -Pn -oA os-detection-aggressive -v
```

```sh
nmap -A -T4 $target -oA os-detection-aggressive -v
```

```sh
nmap -A -T4 $target -Pn -oA os-detection-aggressive -v
```

<!-- Info {{{-->
> [!info]-
>
> `-A` include
>
> - `-O`: Enable OS Detection
> - `-sV`: Service Detection
> - `-sC`: Default Scripts
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- TCP Scan {{{-->
## TCP Scan

<!-- Top 10 TCP Port Scan {{{-->
### Top 10 TCP Port Scan

Scan the most frequent TCP ports

```sh
sudo nmap $target --top-ports=10 -oA tcp-ports-top-10 -v
```

<!-- Tip {{{-->
> [!tip]-
>
> Disable on closed ports:
>
> - ICMP echo requests (`-Pn`)
> - DNS resolution (`-n`)
> - ARP ping scan (`--disable-arp-ping`).
>
> ```sh
> sudo nmap $target --top-ports=10 -Pn -n --disable-arp-ping -oA tcp-ports-top-10 -v
> ```
<!-- }}} -->

<!-- Info {{{-->
> [!info]- Top 10 TCP Ports
>
> Top 10 TCP Ports, ranked in the `nmap-services` file
>
> | Port     | SERVICE       |
> | -------- | ------------- |
> | 21/tcp   | ftp           |
> | 22/tcp   | ssh           |
> | 23/tcp   | telnet        |
> | 25/tcp   | smtp          |
> | 80/tcp   | http          |
> | 110/tcp  | pop3          |
> | 139/tcp  | netbios-ssn   |
> | 443/tcp  | https         |
> | 445/tcp  | microsoft-ds  |
> | 3389/tcp | ms-wbt-server |
<!-- }}} -->

<!-- }}} -->

<!-- Open Port Discovery {{{-->
### Open Port Discovery

Discover open ports on the target machine

```sh
nmap $target --open -oA tcp-open-ports -v
```

Discover open ports on the target machine with service detection

```sh
nmap -sV $target --open -oA tcp-open-ports-sv -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-sV`: Enable service/version detection
> - `--open`: Scan open ports only
> - `-oA`: Save output in all fomats
<!-- }}} -->

<!-- }}} -->

<!-- Full Port Scan {{{-->
### Full Port Scan

Run a full port scan for services running on non-standard ports

```sh
nmap $target -p- --open -oA tcp-port-full -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-p-`: Scan all ports
> - `--open`: Scan open ports only
> - `-oA`: Save output in all fomats
<!-- }}} -->

<!-- }}} -->

<!-- Script Scan {{{-->
### Script Scan

Run a script scan on discovered ports
(*e.g., `22`, `80`*)

```sh
nmap -sC $target -p <port> -oA tcp-script-scan -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-sC`: Run default NSE scripts (*auth, banner grabbing, vuln detection, etc.*)
> - `-p 20,80`: Scan specified ports only
> - `-oA`: Save output in all fomats
<!-- }}} -->

<!-- }}} -->

<!-- TCP Connect Scan {{{-->
### TCP Connect Scan

**TCP Connect Scan** (`-sT`) uses the three-way hansdhake to determine
if a port is open

```sh
sudo nmap $target -p 443 -oA tcp-connect -v
```

```sh
sudo nmap $target -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT -oA tcp-connect-trace -v
```
<!-- }}} -->

___
<!-- }}} -->

<!-- UDP Scan {{{-->
## UDP Scan

<!-- Warning {{{-->
> [!warning]
>
> UDP scans may take a long time
>
> ```sh
> --max-retries 0
> ```
<!-- }}} -->

<!-- Quick Scan {{{-->
### Quick Scan

Perform a quick aggressive scan

```sh
nmap -sU -sV $target -T5 -oA udp-quick-scan -v
```

<!-- Info {{{-->
> [!info]-
>
> -`sU`: Perform UDP scan
> -`sV`: Version detection
> -`T5`: Insane speed/aggressiveness
<!-- }}} -->

<!-- }}} -->

<!-- Top 100 UDP Ports {{{-->
### Top 100 UDP Ports

Scan top 100 UDP ports

```sh
sudo nmap $target -sU -F -oA udp-port-top-100 -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-sU`: Perform UDP scan
> - `-F`: Scan top 100 ports
<!-- }}} -->

<!-- }}} -->

<!-- All UDP Ports {{{-->
### All UDP Ports

Scan all UDP ports

```sh
sudo nmap -sU $target -p- -oA udp-port-all -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-sU`: Perform UDP scan
> - `-p-`: Scan all ports
<!-- }}} -->

<!-- }}} -->

<!-- Specific UDP Port {{{-->
### Specific UDP Port

Scan specific UDP port

```sh
sudo nmap -sU $target -p <port> -Pn -n --disable-arp-ping --packet-trace --reason -oA udp-port-specific -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-sU`: UDP scan
> - `-Pn`: Disable ICMP echo request
> - `-n`: Disable DNS resolution
> - `--disable-arp-ping`: Disable ARP ping
> - `--packet-trace`: Show all packets sent and received
> - `-p 137`: Scan specified port
> - `--reason`: Display reason
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
