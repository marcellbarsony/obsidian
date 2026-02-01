---
id: Enumeration
aliases: []
tags:
  - Networking/Services/FTP/Enumeration
links: "[[FTP]]"
---

# Enumeration

___

<!-- Service {{{-->
## Service

[[Nmap]] — Identify an FTP server

```sh
nmap $target -p 21,2121 -oA ftp-identify
```

[[Nmap]] — Identify FTP server features
(*default FTP unauthantecated script scan*)

```sh
sudo nmap -sC -sV $target -p 21,2121 -A --script-trace -oA ftp-default-script
```

[[Nmap]] — Run all FTP scripts

```sh
nmap $target -p 21,2121 --script ftp-* -oA ftp-script-all
```

[[Metasploit]] — [FTP Version Scanner](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/ftp_version/)

```sh
use auxiliary/scanner/ftp/ftp_version
```

<!-- Info {{{-->
> [!info]-
>
> - `-sC`: Default script scan
> - `-sV`: Version scan
> - `-A`: Aggressive scan
> - `--script-trace`: Trace the progress of the NSE script (*optional*)
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/ftp/ftp_version
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 21
> ```
> ```sh
> run
> ```
> ```sh
> exit
> ```
<!-- }}} -->

<!-- Banner {{{-->
### Banner

[[Netcat]] — Grab the FTP banner

```sh
nc -nv $target 21
```

```sh
nc -nv $target 2121
```

[[Telnet/General|Telnet]] —
Grab the FTP banner

```sh
telnet $target 21
```

```sh
telnet $target 2121
```

<!-- }}} -->

<!-- FTP Bounce Attack {{{-->
### FTP Bounce Attack

[[Nmap]] — Detect
[[FTP/Exploitation#FTP Bounce Attack|FTP Bounce Attack]]
([ftp-bounce](https://nmap.org/nsedoc/scripts/ftp-bounce.html))

```sh
nmap $target -p 21,2121 --script ftp-bounce -oA ftp-script-bounce
```

[[Nmap]] — Perform
[TCP FTP Bounce Scan](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)

```sh
nmap -b $target:<port> <target_network> -oA ftp-bounce-scan
```

[[Metasploit]] — Detect
[[FTP/Exploitation#FTP Bounce Attack|FTP Bounce Attack]]
(*[ftpbounce](https://www.rapid7.com/db/modules/auxiliary/scanner/portscan/ftpbounce/)*)

```sh
use auxiliary/scanner/ftp/ftp_bounce
```

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

<!-- }}} -->

<!-- Certificate {{{-->
### Certificate

Update the connection to TLS, display the server's

- TLS certificate (e.g., *hostname*, *e-mail*, *etc*.)
- connection details

```sh
openssl s_client -connect $target:21 -starttls ftp
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> openssl s_client -connect crossfit.htb:21 -starttls ftp
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Anonymous Authentication {{{-->
## Anonymous Authentication

FTP may allow connection without needing to specific identity

[[Metasploit]] — [Anonymous FTP Access Detection](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/anonymous/)

```sh
use auxiliary/scanner/ftp/anonymous
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/ftp/anonymous
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 21
> ```
> ```sh
> run
> ```
> ```sh
> exit
> ```
<!-- }}} -->

Anonymous login

```sh
ftp $target
```
```sh
ftp $target [port]
```
```sh
ftp $target [port] -p
```

<!-- Info {{{-->
> [!info]-
>
> - `-p`: Use passive mode in environments
> where a firewall prevents connections from the outside world
> back to the client machine
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ftp -p 10.129.42.253
> ```
>
> ```sh
> Connected to 10.129.42.253.
> 220 (vsFTPd 3.0.3)
> Name (10.129.42.253:user): anonymous
> 230 Login successful.
> Remote system type is UNIX.
> Using binary mode to transfer files.
> ```
<!-- }}} -->

Anonymous [[Usage#Web Browser Connection|Browser Login]]

```sh
ftp://anonymous:anonymous@$target
```

___
<!-- }}} -->

<!-- CVE Vulnerabilities {{{-->
## CVE Vulnerabilities

[[Metasploit]] —
BisonWare BisonFTP Server 3.5 Directory Traversal Information Disclosure
(*[bison_ftp_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/bison_ftp_traversal/)*)

```sh
use auxiliary/scanner/ftp/bison_ftp_traversal
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/ftp/bison_ftp_traversal
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 21
> ```
> ```sh
> run
> ```
> ```sh
> exit
> ```
<!-- }}} -->

[[Metasploit]] —
ColoradoFTP Server 1.3 Build 8 Directory Traversal Information Disclosure
(*[colorado_ftp_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/colorado_ftp_traversal/)*)

```sh
use auxiliary/scanner/ftp/colorado_ftp_traversal
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/scanner/ftp/colorado_ftp_traversal
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set RPORT 21
> ```
> ```sh
> run
> ```
> ```sh
> exit
> ```
<!-- }}} -->

[[Metasploit]] —
Titan FTP XCRC Directory Traversal Information Disclosure
(*[titanftp_xcrc_traversal](https://www.rapid7.com/db/modules/auxiliary/scanner/ftp/titanftp_xcrc_traversal/)*)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> use auxiliary/scanner/ftp/titanftp_xcrc_traversal
> set RHOSTS $target
> set RPORT 21
> run
> exit
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Directories {{{-->
## Directories

FTP servers can have default or common directories
that may contain sensitive information

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[Dirbuster#Directories|Dirbuster]]
> - [[SecLists#Directories|SecLists]]
<!-- }}} -->

[[Gobuster]] — Discover directories

```sh
gobuster dir -u ftp://$target -w <wordlist.txt>
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists - Dirbuster General Lowercase
>
> ```sh
> gobuster dir \
> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
> -u ftp://$target
> ```
> ```sh
> gobuster dir \
> -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
> -u ftp://$target
> ```
>
> Wordlists - Seclists General Lowercase
>
> ```sh
> gobuster dir \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt
> -u ftp://$target
> ```
> ```sh
> gobuster dir \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
> -u ftp://$target
> ```
> ```sh
> gobuster dir \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt
> -u ftp://$target
> ```
> ```sh
> gobuster dir \
> -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt
> -u ftp://$target
> ```
<!-- }}} -->

<!-- Info {{{-->
> [!info]-
>
> - `-u`: Specify URL
<!-- }}} -->

[[Ffuf]] — Discover directories

```sh
ffuf -u ftp://$target/FUZZ -w <wordlist.txt>
```

___
<!-- }}} -->
