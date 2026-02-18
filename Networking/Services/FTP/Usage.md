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

<!-- FTP {{{-->
### FTP

Connect to FTP

```sh
ftp $target [port]
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ftp ftp.example.com
> ```
<!-- }}} -->

Connect to FTP (*Active mode*)

```sh
ftp -A $target [port]
```

Connect to FTP (*specify user*)

```sh
ftp <user>@$target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ftp user@ftp.example.com
> ```
<!-- }}} -->

Connect to FTP (*non-interactive mode*)

```sh
ftp -n $target
```

<!-- }}} -->

<!-- LFTP {{{-->
### LFTP Connection

Connect using [lftp](https://linux.die.net/man/1/lftp)

```sh
lftp <ip>
```

<!-- Example {{{-->
> [!example]-
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

<!-- Web Browser {{{-->
### Web Browser

Access the FTP server using a web browser

```sh
ftp://<username>:<password>@<ip>
```

<!-- }}} -->

<!-- Localhost {{{-->
### Localhost

Access local FTP server

```sh
ftp ftp://<user>:<password>@localhost
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

Toggle passive mode

```sh
passive
```

```sh
passive off
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

Set transmission to binary
(*move raw bytes*)

```sh
binary
```

Set transmission to ASCII
(*move files as text*)

```sh
ascii
```

___
<!-- }}} -->

<!-- File Operations {{{-->
## File Operations

<!-- List {{{-->
### List

List all files (*including hidden files*)

```sh
ftp> ls -a
```

List files recursively
(*if [[FTP/General#Recursive Listing|Recursive Listing]] is enabled*)

```sh
ftp> ls -R
```
<!-- }}} -->

<!-- Download {{{-->
### Download

Download a file

```sh
ftp> get Important\ Notes.txt
```

Download all files
(*[[Networking/Services/FTP/Exploitation#Anonymous Login|Anonymous Login]]*)

```sh
wget -m ftp://anonymous:anonymous@$target
```

```sh
wget -m --no-passive ftp://anonymous:anonymous@$target
```

Supply credentials with special characters

```sh
wget -r --user="<user>" --password="<user>" ftp://$target
```

<!-- }}} -->

<!-- Upload {{{-->
### Upload

Uploading files may allow for [LFI vulnerabilities](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
leading to [Remote Command Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution)

```sh
ftp> put <file.ext>
```

<!-- }}} -->

___
<!-- }}} -->
