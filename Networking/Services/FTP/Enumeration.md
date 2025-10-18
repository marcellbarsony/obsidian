---
id: Enumeration
aliases: []
tags:
  - Networking/Services/FTP/Enumeration
links: "[[FTP]]"
---

# Enumeration

<!-- Checklist {{{-->
## Checklist

- [ ] [[#Nmap|Nmap scan]]
    - [ ] [[#Nmap#FTP Server|FTP Server]]
    - [ ] [[#Nmap#FTP Server Features|FTP Server Features]]
        - [ ] [[#FTP Bounce Attack|FTP Bounce Attack]]
- [ ] [[#Banner Grabbing|Banner Grabbing]]
    - [ ] [[#Banner Grabbing#Netcat|Netcat]]
    - [ ] [[#Banner Grabbing#Telnet|Telnet]]
- [ ] [[#Certificate|TLS Certificate]]
- [ ] [[#Default and Common Directories|Default & Common Directories]]

___

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

### FTP Server

Identify an FTP server

```sh
nmap -p 21 <target> -oA ftp-identify
```

### FTP Server Features

Identify FTP server features (*default FTP unauthantecated script scan*)

```sh
sudo nmap -sC -sV -p 21 -A <target> --script-trace -oA ftp-default-script
```

<!-- Info {{{-->
> [!info]-
>
> - `-sC`: Default script scan
> - `-sV`: Version scan
> - `-A`: Aggressive scan
> - `--script-trace`: Trace the progress of the NSE script (*optional*)
<!-- }}} -->

Run all FTP scripts

```sh
nmap --script ftp-* -p 21 <target_ip> -oA ftp-all-scripts
```

### FTP Bounce Attack

Check if the FTP server allows
[[Exploitation#FTP Bounce Attack|FTP Bounce Attack]]
via the
[ftp-bounce](https://nmap.org/nsedoc/scripts/ftp-bounce.html)
script

```sh
nmap -p 21 --script ftp-bounce <target> -oA ftp-bounce
```

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

### Netcat

Grab the FTP banner with [[netcat]]

```sh
nc -nv <target> 21
```

### Telnet

Grab the FTP banner with [[Networking/Services/Telnet/General|Telnet]]

```sh
telnet <target> 21
```

___

<!-- }}} -->

<!-- Certificate {{{-->
## Certificate

Update the connection to TLS, display the server's:

- TLS certificate (e.g., *hostname*, *e-mail*, *etc*.)
- connection details

```sh
openssl s_client -connect <target>:21 -starttls ftp
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> openssl s_client -connect crossfit.htb:21 -starttls ftp
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

Consoleless MFS enumeration

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/anonymous
> set RHOSTS <target>
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/ftp_version
> set RHOSTS <target>
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/bison_ftp_traversal
> set RHOSTS <target>
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/colorado_ftp_traversal
> set RHOSTS <target>
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/titanftp_xcrc_traversal
> set RHOSTS <target>
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Default and Common Directories {{{-->
## Default and Common Directories

FTP servers can have default or common directories
that may contain sensitive information — [[Gobuster]]

```sh
gobuster dir -u ftp://<ip> -w <dirlist.txt>
```

___

<!-- }}} -->
