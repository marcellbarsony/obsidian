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

Identify an FTP server

```sh
nmap -p 21 <target> -oA ftp-identify
```

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
nmap --script ftp-* -p 21 <target_ip> -oA ftp-script-all
```

<!-- FTP Bounce Attack {{{-->
### FTP Bounce Attack

Detect
[[Exploitation#FTP Bounce Attack|FTP Bounce Attack]]
([ftp-bounce](https://nmap.org/nsedoc/scripts/ftp-bounce.html))

```sh
nmap -p 21 --script ftp-bounce <target> -oA ftp-script-bounce
```

Perform
[TCP FTP Bounce Scan](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)

```sh
nmap -b <ftp_server_ip>:<port> <target_network>
```

___

<!-- }}} -->

<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit

[[Exploitation#FTP Bounce Attack|FTP Bounce]] Port Scanner
([ftpbounce](https://www.rapid7.com/db/modules/auxiliary/scanner/portscan/ftpbounce/))

<!-- Example {{{-->
> [!example]-
>
> ```sh
> use auxiliary/scanner/ftp/ftp_bounce
> ```
> ```sh
> set RHOSTS <FTP_server>
> ```
> ```sh
> set RPORT <FTP_port>
> ```
> ```sh
> run
> ```
<!-- }}} -->

[[Exploitation#Anonymous Login|Anonymous FTP Access]] Detection
([anonymous](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/anonymous/))

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

FTP Version Scanner
([ftp_version](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/ftp_version/))

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

BisonWare BisonFTP Server 3.5 Directory Traversal Information Disclosure
([bison_ftp_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/bison_ftp_traversal/))

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

ColoradoFTP Server 1.3 Build 8 Directory Traversal Information Disclosure
([colorado_ftp_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/colorado_ftp_traversal/))

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

Titan FTP XCRC Directory Traversal Information Disclosure
([titanftp_xcrc_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/titanftp_xcrc_traversal/))

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

FTP Authentication Scanner
([ftp_login](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/ftp_login/))

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msf > use auxiliary/scanner/ftp/ftp_login
> msf auxiliary(ftp_login) > show actions
> msf auxiliary(ftp_login) > set ACTION <action_name>
> msf auxiliary(ftp_login) > show options
> msf auxiliary(ftp_login) > run
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Grab the FTP banner with [[netcat]]

```sh
nc -nv <target> 21
```

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

<!-- Directories {{{-->
## Directories

FTP servers can have default or common directories
that may contain sensitive information

Discover directories with [[Gobuster]]

```sh
gobuster dir -u ftp://<ip> -w <dirlist.txt>
```

___

<!-- }}} -->
