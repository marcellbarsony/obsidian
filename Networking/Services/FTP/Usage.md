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

### FTP Connection

Connect to FTP

```sh
ftp <ip> [port]
```

### LFTP Connection

Connect using [lftp](https://linux.die.net/man/1/lftp)

```sh
lftp <ip>
```

### Web Browser Connection

Access the FTP server using a web browser

```sh
ftp://<username>:<password>@<ip>
```
<!-- }}} -->

<!-- File Operations {{{-->
## File Operations

### Download Files

Download a file

```sh
ftp> get Important\ Notes.txt
```

Download all files

```sh
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

### Upload Files

Uploading files may allow for [LFI vulnerabilities](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
leading to [Remote Command Execution](https://en.wikipedia.org/wiki/Arbitrary_code_execution)
(RCE)
