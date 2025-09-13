---
id: Host Enumeration
aliases: []
tags: []
---

# Host Enumeration

Enumerate a host with known IP address

## Service Enumeration

Enumerate services on the target machine

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


