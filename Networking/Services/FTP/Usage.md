---
id: Usage
aliases: []
tags:
  - Networking/Services/FTP/Usage
links: "[[FTP]]"
---

# Usage

___

<!-- Connect {{{-->
## Connect

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

<!-- Exit {{{-->
### Exit

```sh
bye
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> >bye
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Settings {{{-->
## Settings

Set passive mode

```sh
passive
```

Disable interactive mode

```sh
dir
```

```sh
prompt
```

```sh
mget *
```

Set transmission to binary —
Move raw bytes

```sh
binary
```

Set transmission to ASCII —
Move files as text

```sh
ascii
```

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
(*if [[Networking/Services/FTP/General#Recursive Listing|Recursive Listing]] is enabled*)

```sh
ftp> ls -R
```

<!-- Download Files {{{-->
### Download Files

Download a file

```sh
ftp> get Important\ Notes.txt
```

Download all files
(*[[Networking/Services/FTP/Exploitation#Anonymous Login|Anonymous Login]]*)

```sh
wget -m ftp://anonymous:anonymous@<target>
```

```sh
wget -m --no-passive ftp://anonymous:anonymous@<target>
```

Supply credentials with special characters

```sh
wget -r --user="<user>" --password="<user>" ftp://<target>
```

<!-- }}} -->

<!-- Upload Files {{{-->
### Upload Files

Uploading files may allow for [LFI vulnerabilities](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
leading to [Remote Command Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution)

```sh
ftp> put <file.ext>
```

<!-- }}} -->

___
<!-- }}} -->
