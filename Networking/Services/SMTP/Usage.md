---
id: Usage
aliases: []
tags:
  - Networking/Services/SMTP/Usage
---

# Usage

<!-- Commands {{{-->
## Commands

The communication is done by special commands causing the **SMTP Server** to
perform the required action

<!-- Example {{{-->
> [!example]-
>
> **SMTP Commands** used in e-mail communication between a client (e-mail app)
> and a server
>
>| Command      | Description                                                                             |
>| -----------  | --------------------------------------------------------------------------------------- |
>| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client                             |
>| `HELO`       | The client logs in with its computer name and thus starts the session                   |
>| `MAIL FROM`  | The client names the email sender                                                       |
>| `RCPT TO`    | The client names the email recipient                                                    |
>| `DATA`       | The client initiates the transmission of the email                                      |
>| `RSET`       | The client aborts the initiated transmission but keeps the connection                   |
>| `VRFY`       | The client checks if a mailbox is available for message transfer                        |
>| `EXPN`       | The client also checks if a mailbox is available for messaging with this command        |
>| `NOOP`       | The client requests a response from the server to prevent disconnection due to time-out |
>| `QUIT`       | The client terminates the session                                                       |
<!-- }}} -->

<!-- Telnet {{{-->
### Telnet

<!-- HELO/EHLO {{{-->
#### HELO/EHLO

[[Networking/Services/Telnet/General|Telnet]] can be used to interact with the
**SMTP** server through TCP connection

```sh
telnet $target <port>
```

The initialization of the session is done with `HELO` or `EHLO`

<!-- Example {{{ -->
> [!example]-
>
> **HELO** & **EHLO**
>
>```sh
>telnet 10.129.14.128 25
>
>Trying 10.129.14.128...
>Connected to 10.129.14.128.
>Escape character is '^]'.
>220 ESMTP Server 
>
>
>HELO mail1.inlanefreight.htb
>
>250 mail1.inlanefreight.htb
>
>
>EHLO mail1
>
>250-mail1.inlanefreight.htb
>250-PIPELINING
>250-SIZE 10240000
>250-ETRN
>250-ENHANCEDSTATUSCODES
>250-8BITMIME
>250-DSN
>250-SMTPUTF8
>250 CHUNKING
>```
<!-- }}} -->

<!-- }}} -->

<!-- VRFY {{{-->
#### VRFY

The `VRFY` command can be used to enumerate existing users on the system

<!-- Example {{{-->
> [!example]-
>
> Connect to the service
>
> ```sh
> telnet 10.129.14.128 25
> ```
> ```sh
> Trying 10.129.14.128...
> Connected to 10.129.14.128.
> Escape character is '^]'.
> 220 ESMTP Server
> ```
>
> Check if user `root` exist
>
> ```sh
> VRFY root
> ```
> ```sh
> 252 2.0.0 root
>
> ```
>
> Check if user `cry0l1t3` exist
> ```sh
> VRFY cry0l1t3
> ```
> ```sh
> 252 2.0.0 cry0l1t3
>
> ```
>
> Check if user `testuser` exist
>
> ```sh
> VRFY testuser
> 252 2.0.0 testuser
>
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
>The **SMTP** server may issue [error code](https://serversmtp.com/smtp-error/)
>`252` and confirm the existence of a user that doesn't exist on the system
<!-- }}} -->

<!-- }}} -->

<!-- Send an Email {{{-->
#### Send an Email

Send an e-mail manually through an **SMTP Server** at IP `10.129.14.128` on port
`25`. The structure of the header is defined in
[RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322).

<!-- Example {{{ -->
> [!example]-
>
> **Send an Email**
>
>```sh
>telnet 10.129.14.128 25
>```
>```sh
>Trying 10.129.14.128...
>Connected to 10.129.14.128.
>Escape character is '^]'.
>220 ESMTP Server
>
>
>EHLO inlanefreight.htb
>
>250-mail1.inlanefreight.htb
>250-PIPELINING
>250-SIZE 10240000
>250-ETRN
>250-ENHANCEDSTATUSCODES
>250-8BITMIME
>250-DSN
>250-SMTPUTF8
>250 CHUNKING
>
>
>MAIL FROM: <cry0l1t3@inlanefreight.htb>
>
>250 2.1.0 Ok
>
>
>RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure
>
>250 2.1.5 Ok
>
>
>DATA
>
>354 End data with <CR><LF>.<CR><LF>
>
>From: <cry0l1t3@inlanefreight.htb>
>To: <mrb3n@inlanefreight.htb>
>Subject: DB
>Date: Tue, 28 Sept 2021 16:32:51 +0200
>Hey man, I am trying to access our XY-DB but the creds don't work.
>Did you make any changes there?
>.
>
>250 2.0.0 Ok: queued as 6E1CF1681AB
>
>
>QUIT
>
>221 2.0.0 Bye
>Connection closed by foreign host.
>```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->
