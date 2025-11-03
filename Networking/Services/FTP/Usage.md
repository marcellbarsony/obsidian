---
id: Usage
aliases: []
tags:
  - Networking/Services/FTP/Usage
links: "[[FTP]]"
---

# Usage

<!-- Connection {{{-->
## Connection

<!-- FTP Connection {{{-->
### FTP Connection

Connect to FTP

```sh
ftp <ip> [port]
```

<!-- }}} -->

<!-- LFTP Connection {{{-->
### LFTP Connection

Connect using [lftp](https://linux.die.net/man/1/lftp)

```sh
lftp <ip>
```

<!-- Example {{{-->
> [!example]-
>
> **LFTP Connection**
>
> ```sh
> lftp 10.10.10.208
> ```
> ```sh
> lftp :~> set ftp:ssl-force true
> lftp :~> set ssl:verify-certificate no
> lftp :~> connect 10.10.10.208
> lftp 10.10.10.208:~> login
> Usage: login <user|URL> [<pass>]
> lftp 10.10.10.208:~> login username Password
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Web Browser Connection {{{-->
### Web Browser Connection

Access the FTP server using a web browser

```sh
ftp://<username>:<password>@<ip>
```

<!-- }}} -->

___

<!-- }}} -->

<!-- File Operations {{{-->
## File Operations

### List Files

List all files (*including hidden files*)

```sh
ftp> ls -a
```

List files recursively
(*if [[General#Recursive Listing|Recursive Listing]] is enabled*)

```sh
ftp> ls -R
```

<!-- Download Files {{{-->
### Download Files

Download a file

```sh
ftp> get Important\ Notes.txt
```

Download all files ([[Exploitation#Anonymous Login|Anonymous Login]])

```sh
wget -m ftp://anonymous:anonymous@10.10.10.98
```

```sh
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

Supply credentials with special characters

```sh
wget -r --user="USERNAME" --password="PASSWORD" ftp://server.com/
```

<!-- }}} -->

<!-- Upload Files {{{-->
### Upload Files

Uploading files may allow for [LFI vulnerabilities](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
leading to [Remote Command Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution)
(RCE)

```sh
ftp> put testupload.txt
```

<!-- }}} -->

___

<!-- }}} -->
