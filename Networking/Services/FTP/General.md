---
id: FTP
aliases:
  - File Transfer Protocol
tags:
  - Networking/Services/FTP/General
links: "[FTP]"
port:
  - 20
  - 21
  - 2020
  - 2121
---

<!-- FTP {{{-->
# FTP

**FTP** ([File Transfer Protocol](https://en.wikipedia.org/wiki/File_Transfer_Protocol))
([RFC 959](https://datatracker.ietf.org/doc/html/rfc959)) is a standard
*plain-text* server-client protocol for file transfer across a computer network.

<!-- Example {{{-->
> [!example]-
>
> Nmap FTP scan
>
> ```sh
> PORT   STATE SERVICE
> 21/tcp open  ftp
> ```
<!-- }}} -->

<!-- FTP Server Return Codes {{{-->
> [!tip]- FTP Server Return Codes
>
> [Wikipedia - List of FTP server return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)
>
<!-- }}} -->

___

<!-- Active vs Passive FTP{{{-->
## Active vs Passive FTP

<!-- Active FTP {{{-->
### Active FTP

The **client** establishes the connection and informs the **server** which
client-side port it can transmit its responses:

1. The FTP **client** initiates the control connection from its port
   *N* to the FTP **server**'s command port (`21`)

2. The **client** listens to port *N+1* and sends the port *N+1* to the
   **server**

> [!warning]
>
> If the client is protected by a firewall, the server cannot reply as
> external connections are blocked
<!-- }}} -->

<!-- Passive FTP {{{-->
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

___

<!-- }}} -->

<!-- vsFTPd {{{-->
# vsFTPd

[vsFTPd](https://security.appspot.com/vsftpd.html) (Very Secure FTP Daemon) is a
secure FTP server for UNIX-like systems.

<!-- Install {{{-->
## Install

[Kali Packages](https://pkg.kali.org/pkg/vsftpd)

```sh
sudo apt install vsftpd
```

[Arch Packages](https://archlinux.org/packages/extra/x86_64/vsftpd/)

```sh
sudo pacman -Syu vsftpd
```
<!-- }}} -->

<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

The default configuration can be found in `/etc/vsftpd.conf`

The file `/etc/ftpusers` can be used to deny certain users
access to the FTP service

<!-- Example {{{-->
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
<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

<!-- Anonymous Login {{{-->
#### Anonymous Login

Optional vsFTPd [settings](http://vsftpd.beasts.org/vsftpd_conf.html) can be set
to allow the [[Networking/Services/FTP/Exploitation#Anonymous Login|Anonymous Login]]

<!-- Danger {{{-->
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
<!-- }}} -->

It is now possible to log in with the `anonymous` username

<!-- Example {{{-->
> [!example]-
>
> **Anonymous Login**
>
> ```sh
> ftp 10.129.14.136
> ```
>
> ```sh
> Connected to 10.129.14.136.
> 220 "Welcome to the vsFTP service."
> Name (10.129.14.136:cry0l1t3): anonymous
>
> 230 Login successful.
> Remote system type is UNIX.
> Using binary mode to transfer files.
> ```
<!-- }}} -->

After the successful anonymous login, the `status`, `debug` and `trace` commands
provide additional information

<!-- Example {{{-->
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
<!-- }}} -->

<!-- }}} -->

<!-- Recursive Listing {{{-->
#### Recursive Listing

`ls_recurse_enable=YES` is often set on the vsFTPd server to have a better
overview of the FTP directory structure

```sh
ls -R
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ---> PORT 10,10,14,4,222,149
> 200 PORT command successful. Consider using PASV.
> ---> LIST -R
> 150 Here comes the directory listing.
> .:
> -rw-rw-r--    1 ftp      ftp      8138592 Sep 14 16:54 Calender.pptx
> drwxrwxr-x    2 ftp      ftp         4096 Sep 14 17:03 Clients
> drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Documents
> drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Employees
> -rw-rw-r--    1 ftp      ftp           41 Sep 14 16:45 Important Notes.txt
> -rw-------    1 ftp      ftp            0 Sep 15 14:57 testupload.txt
>
> ./Clients:
> drwx------    2 ftp      ftp          4096 Sep 16 18:04 HackTheBox
> drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:00 Inlanefreight
>
> ./Clients/HackTheBox:
> -rw-r--r--    1 ftp      ftp         34872 Sep 16 18:04 appointments.xlsx
> -rw-r--r--    1 ftp      ftp        498123 Sep 16 18:04 contract.docx
> -rw-r--r--    1 ftp      ftp        478237 Sep 16 18:04 contract.pdf
> -rw-r--r--    1 ftp      ftp           348 Sep 16 18:04 meetings.txt
>
> ./Clients/Inlanefreight:
> -rw-r--r--    1 ftp      ftp         14211 Sep 16 18:00 appointments.xlsx
> -rw-r--r--    1 ftp      ftp         37882 Sep 16 17:58 contract.docx
> -rw-r--r--    1 ftp      ftp            89 Sep 16 17:58 meetings.txt
> -rw-r--r--    1 ftp      ftp        483293 Sep 16 17:59 proposal.pptx
>
> ./Documents:
> -rw-r--r--    1 ftp      ftp         23211 Sep 16 18:05 appointments-template.xlsx
> -rw-r--r--    1 ftp      ftp         32521 Sep 16 18:05 contract-template.docx
> -rw-r--r--    1 ftp      ftp        453312 Sep 16 18:05 contract-template.pdf
>
> ./Employees:
> 226 Directory send OK.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- TFTP {{{-->
# TFTP

**Trivial File Transfer Protocol**
([TFTP](https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol))
is an unauthenticated, UDP protocol that performs file transfers
between client and server processes.

<!-- Usage {{{-->
## Usage

| Commands   | Description                                                |
| ---------- | ---------------------------------------------------------- |
| `connect`  | Sets the remote host, and optionally the port              |
| `get`      | Transfers file(s) from the remote host to the local host   |
| `put`      | Transfers file(s) from the local host onto the remote host |
| `quit`     | Exits TFTP                                                 |
| `status`   | Shows FTFP status (e.g., transfer mode (ascii or binary)   |
| `verbose`  | Toggles verbose mode                                       |

<!-- }}} -->

___

<!-- }}} -->
