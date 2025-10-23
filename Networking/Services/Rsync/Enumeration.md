---
id: Rsync
aliases: []
tags:
  - Networking/Services/Rsync/Enumeration
links: "[[Services]]"
---

# Enumeration

Enumerate Rsync server for and accessible [[General#Modules|modules]] (*shares*)
public exploits

<!-- Service {{{-->
## Service

Identify Rsync server on a target host

```sh
nmap -p 873 <target> -oA rsync-identify
```

> [!example]-
>
> ```sh
> sudo nmap -sV -p 873 127.0.0.1
> ```
> ```sh
> Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 09:31 EDT
> Nmap scan report for localhost (127.0.0.1)
> Host is up (0.0058s latency).
>
> PORT    STATE SERVICE VERSION
> 873/tcp open  rsync   (protocol version 31)
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
> ```

Identify R-Services

```sh
sudo nmap -sV -p 512,513,514 <target> -oA rsync-services
```

> [!example]-
>
> ```sh
> sudo nmap -sV -p 512,513,514 10.0.17.2
> ```
>
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2022-12-02 15:02 EST
> Nmap scan report for 10.0.17.2
> Host is up (0.11s latency).
>
> PORT    STATE SERVICE    VERSION
> 512/tcp open  exec?
> 513/tcp open  login?
> 514/tcp open  tcpwrapped
>
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> Nmap done: 1 IP address (1 host up) scanned in 145.54 seconds
> ```

Identify outdated Rsync version for public exploits
([rsync-list-modules](https://nmap.org/nsedoc/scripts/rsync-list-modules.html))

```sh
nmap -sV --script=rsync-list-modules <target_host> -oA rsync-script-list-modules
```

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Grab banner and accessible [[General#Modules|modules]] with [[Netcat]]

```sh
nc -nv <target> 873
```

> [!example]-
>
> Expected output format
>
> ```sh
> (UNKNOWN) [127.0.0.1] 873 (rsync) open
> @RSYNCD: 31.0
> @RSYNCD: 31.0
> #list
> raidroot
> @RSYNCD: AUTHREQD 7H6CqsHCPG06kRiFkKwD8g
> ```
>
> - The share `raidroot` can be enumerated further
> - `@RSYNCD: AUTHREQD`: Password needed

___

<!-- }}} -->

<!-- Modules {{{-->
## Modules

Enumerate Rsync [[General#Modules|modules]] to understand their structure
and find misconfiguration or sensitive information

List modules available for Rsync synchronization with [[Nmap]]
([rsync-list-modules](https://nmap.org/nsedoc/scripts/rsync-list-modules.html))

```sh
nmap -sV --script "rsync-list-modules" -p 873 <target> -oA rsync-script-list-modules
```

<!-- Example {{{-->
> [!example]-
>
> Script output format
>
> ```sh
> PORT    STATE SERVICE
> 873/tcp open  rsync
> | rsync-list-modules:
> |   www            	www directory
> |   log            	log directory
> |_  etc            	etc directory
> ```
<!-- }}} -->

List modules with [[Metasploit]]
([modules-list](https://www.rapid7.com/db/modules/auxiliary/scanner/rsync/modules_list/))


```sh
use auxiliary/scanner/rsync/modules_list
```

<!-- Exmaple {{{-->
> [!example]-
>
> This module connects to and negotiates with an rsync server,
> lists the available modules and, optionally,
> determines if the module requires a password to access
>
> ```sh
> msf > use auxiliary/scanner/rsync/modules_list
> msf auxiliary(modules_list) > show actions
>     ...actions...
> msf auxiliary(modules_list) > set ACTION < action-name >
> msf auxiliary(modules_list) > show options
>     ...show and set options...
> msf auxiliary(modules_list) > run
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Shared Folders {{{-->
## Shared Folders

Rsync modules represent directory shares and may be protected with a password

```sh
rsync <target>::
```

```sh
rsync -av --list-only rsync://<target>/<module_name>
```

> [!example]-
>
> ```sh
> rsync -av --list-only rsync://127.0.0.1/dev
> ```
>
> ```sh
> receiving incremental file list
> drwxr-xr-x             48 2022/09/19 09:43:10 .
> -rw-r--r--              0 2022/09/19 09:34:50 build.sh
> -rw-r--r--              0 2022/09/19 09:36:02 secrets.yaml
> drwx------             54 2022/09/19 09:43:10 .ssh
>
> sent 25 bytes  received 221 bytes  492.00 bytes/sec
> total size is 0  speedup is 0.00
> ```

> [!tip]-
>
> [[Usage#Synchronize|Synchronize]]

___

<!-- }}} -->
