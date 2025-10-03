---
id: FTP
aliases:
  - File Transfer Protocol
tags:
  - Networking/Services/FTP/General
links: "[[Services]]"
port:
  - 20
  - 21
---

<!-- File Transfer Protocol (FTP) {{{-->
# File Transfer Protocol (FTP)

**FTP** ([RFC 959](https://datatracker.ietf.org/doc/html/rfc959)) is a standard
*plain-text* server-client protocol for file transfer across a computer network.

```sh
PORT   STATE SERVICE
21/tcp open  ftp
```

- [Wikipedia - List of FTP server return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)

<!-- Active vs Passive FTP {{{-->
## Active vs Passive FTP

### Active FTP

The **client** establishes the connection and informs the **server** which
client-side port it can transmit its responses:

1. The FTP **client** initiates the control connection from its port
   *N* to the FTP **server**'s command port (`21`)

2. The **client** listens to port *N+1* and sends the port *N+1* to the
   **server**

> [!note]
> If the client is protected by a firewall, the server cannot reply as
> external connections are blocked

### Passive FTP

The **server** announces a port throrugh which the client can establish the data
channel:

1. The FTP **client** initiates the control connection from its port
   *N* to port `21` of the FTP **server**

2. The **client** issues a *passv* command

3. The **server** sends one of its port number (*M*) to the **client**

4. The **client** initiate the data connection from its port *P* to port *M*
   of the **server**
<!-- }}} -->
<!-- }}} -->

<!-- vsFTPd {{{-->
# vsFTPd

[vsFTPd](https://security.appspot.com/vsftpd.html) (Very Secure FTP Daemon) is a
secure FTP server for UNIX-like systems.

<!-- Installation {{{-->
## Installation

Install `vsftpd` on Debian-based systems

```sh
sudo apt install vsftpd
```

Install `vsftpd` on Arch

```sh
sudo pacman -Syu vsftpd
```
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

The default configuration can be found in `/etc/vsftpd.conf`

The file `/etc/ftpusers` can be used to deny certain users access to the FTP
service

> [!example]-
>
> **Configuration**
>
>```sh
>cat /etc/ftpusers
>```
>```sh
>guest
>john
>kevin
>```

### Dangerous Settings

#### Anonymous Login

Optional vsFTPd [settings](http://vsftpd.beasts.org/vsftpd_conf.html) can be set
to allow the [[Exploitation#Anonymous Login|Anonymous Login]].

> [!danger]-
>
> **Dangerous Settings**
>
>| Setting                      | Description                                                      |
>| ---------------------------- | ---------------------------------------------------------------- |
>| anonymous_enable=YES         | Allowing anonymous login                                         |
>| anon_upload_enable=YES       | Allowing anonymous to upload files                               |
>| anon_mkdir_write_enable=YES  | Allowing anonymous to create new directories                     |
>| no_anon_password=YES         | Do not ask anonymous for password                                |
>| anon_root=/home/username/ftp | Directory for anonymous                                          |
>| write_enable=YES             | Allow commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE |
>| local_enable=YES             | Enable local users to login                                      |
>| chown_uploads=YES            | Change ownership of anonymously uploaded files                   |
>| chown_username=username      | User who is given ownership of anonymously                       |

It is now possible to log in with the `anonymous` username

> [!example]-
>
> **Anonymous Login**
>
>```sh
>ftp 10.129.14.136
>```
>
>```sh
>Connected to 10.129.14.136.
>220 "Welcome to the vsFTP service."
>Name (10.129.14.136:cry0l1t3): anonymous
>
>230 Login successful.
>Remote system type is UNIX.
>Using binary mode to transfer files.
>```

After the successful anonymous login, the `status`, `debug` and `trace` commands
provide additional information.

> [!example]-
>
> **Status & Debug & Trace commands**
>
>```sh
>ftp> debug
>Debugging on (debug=1).
>
>ftp> trace
>Packet tracing on.
>
>ftp> ls
>---> PORT 10,10,14,4,188,195
>200 PORT command successful. Consider using PASV.
>---> LIST
>150 Here comes the directory listing.
>-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
>drwxrwxr-x    2 1002     1002         4096 Sep 14 17:03 Clients
>drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
>drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
>-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
>226 Directory send OK.
>```

#### Recursive Listing

`ls_recurse_enable=YES` is often set on the vsFTPd server to have a better
overview of the FTP directory structure

```sh
ls -R
```
<!-- }}} -->
<!-- }}} -->

<!-- TFTP {{{-->
# TFTP

**Trivial File Transfer Protocol** ([TFTP](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol))
is an unauthenticated, UDP protocol that performs file transfers between client
and server processes.

## Usage

| Commands | Description                                                |
| -------- | ---------------------------------------------------------- |
| connect  | Sets the remote host, and optionally the port              |
| get      | Transfers file(s) from the remote host to the local host   |
| put      | Transfers file(s) from the local host onto the remote host |
| quit     | Exits TFTP                                                 |
| status   | Shows FTFP status (e.g., transfer mode (ascii or binary)   |
| verbose  | Toggles verbose mode                                       |
<!-- }}} -->
