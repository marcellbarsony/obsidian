---
id: Usage
aliases: []
tags:
  - Networking/Services/SMTP/Usage
---

# Usage

___

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

<!-- Netcat {{{-->
### Netcat

[[Netcat]] — Test connection to the SMTP Server

```sh
ncat $target 25
```

___
<!-- }}} -->

<!-- Telnet {{{-->
### Telnet

[[Networking/Services/Telnet/General|Telnet]] can be used to interact with the
**SMTP** server through TCP connection

<!-- Connect {{{-->
#### Connect

Connect to the SMTP server

```sh
telnet $target <port>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> telnet target.com 25
> ```
>
> Basic SMTP conversation
>
> ```sh
> EHLO attacker.com
> MAIL FROM:<sender@attacker.com>
> RCPT TO:<victim@target.com>
> DATA
> Subject: Test
> Test message
> .
> QUIT
> ```
<!-- }}} -->

<!-- }}} -->

<!-- HELO {{{-->
#### HELO

`HELO`/`EHLO` — Initialize session

```sh
HELO <target_server>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> telnet 10.129.14.128 25
> ```
>
> ```sh
> Trying 10.129.14.128...
> Connected to 10.129.14.128.
> Escape character is '^]'.
> 220 ESMTP Server
> ```
>
> ```sh
> HELO mail1.inlanefreight.htb
> ```
>
> ```sh
> 250 mail1.inlanefreight.htb
> ```
>
> ```sh
> EHLO mail1
> ```
>
> ```sh
> 250-mail1.inlanefreight.htb
> 250-PIPELINING
> 250-SIZE 10240000
> 250-ETRN
> 250-ENHANCEDSTATUSCODES
> 250-8BITMIME
> 250-DSN
> 250-SMTPUTF8
> 250 CHUNKING
> ```
<!-- }}} -->

<!-- }}} -->

<!-- VRFY {{{-->
#### VRFY

`VRFY` — Enumerate existing users on the system

<!-- Warning {{{-->
> [!warning]
>
>The **SMTP** server may issue [error code](https://serversmtp.com/smtp-error/)
>`252` and confirm the existence of a user that doesn't exist on the system
<!-- }}} -->

```sh
VRFY <user>
```

<!-- Example {{{-->
> [!example]-
>
> Check if user `root` exist
>
> ```sh
> VRFY root
> ```
> ```sh
> 252 2.0.0 root
> ```
>
> Check if user `www-data` exist
>
> ```sh
> VRFY www-data
> ```
> ```sh
> 252 2.0.0 www-data
> ```
>
> Check if user `testuser` exist
>
> ```sh
> VRFY testuser
> ```
>
> ```sh
> 550 5.1.1 <testuser>: Recipient address rejected: User unknown in local recipient table
> ```sh
<!-- }}} -->

<!-- }}} -->

<!-- EXPN {{{-->
#### EXPN

`EXPN` — Enumerate existing users and users on a distribution list

<!-- Warning {{{-->
> [!warning]
>
>The **SMTP** server may issue [error code](https://serversmtp.com/smtp-error/)
>`252` and confirm the existence of a user that doesn't exist on the system
<!-- }}} -->

```sh
EXPN <user>
```

```sh
EXPN <distribution_list>
```

<!-- Example {{{-->
> [!example]-
>
> Check if user `john` exist
>
> ```sh
> EXPN john
> ```
> ```sh
> 250 2.1.0 john@inlanefreight.htb
> ```
>
> List users of the `support-team` distribution list
>
> ```sh
> EXPN support-team
> ```
> ```sh
> 250 2.0.0 carol@inlanefreight.htb
> 250 2.1.5 elisa@inlanefreight.htb
> ```
<!-- }}} -->

<!-- }}} -->

<!-- RCPT TO {{{-->
#### RCPT TO

Identify the recipient of an e-mail message

```sh
RCPT TO: john
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MAIL FROM:test@htb.com
> ```
> ```sh
> it is
> 250 2.1.0 test@htb.com... Sender ok
> ```
>
> ```sh
> RCPT TO:julio
> ```
> ```sh
> 550 5.1.1 julio... User unknown
> ```
>
> ```sh
> RCPT TO:kate
> ```
> ```sh
> 550 5.1.1 kate... User unknown
> ```
>
> ```sh
> RCPT TO:john
> ```
> ```
> 250 2.1.5 john... Recipient ok
> ```
<!-- }}} -->

<!-- }}} -->

<!-- USER {{{-->
#### USER

Enumerate user (*[[POP3/Usage#POP3 Commands|POP3 Commands]]*)

```sh
USER <user>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> USER john
> ```
> ```sh
> +OK
> ```
>
> ```sh
> USER julio
> ```
> ```sh
> -ERR
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Send an Email {{{-->
#### Send an Email

Send an e-mail manually through an **SMTP Server** at IP `10.129.14.128` on port
`25`. The structure of the header is defined in
[RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)

<!-- Example {{{-->
> [!example]-
>
> **Send an Email**
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
>
> ```sh
> EHLO inlanefreight.htb
> ```
>
> ```sh
> 250-mail1.inlanefreight.htb
> 250-PIPELINING
> 250-SIZE 10240000
> 250-ETRN
> 250-ENHANCEDSTATUSCODES
> 250-8BITMIME
> 250-DSN
> 250-SMTPUTF8
> 250 CHUNKING
>
> MAIL FROM: <cry0l1t3@inlanefreight.htb>
>
> 250 2.1.0 Ok
>
>
> RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure
>
> 250 2.1.5 Ok
>
>
> DATA
>
> 354 End data with <CR><LF>.<CR><LF>
>
> From: <cry0l1t3@inlanefreight.htb>
> To: <mrb3n@inlanefreight.htb>
> Subject: DB
> Date: Tue, 28 Sept 2021 16:32:51 +0200
> Hey man, I am trying to access our XY-DB but the creds don't work.
> Did you make any changes there?
> .
>
> 250 2.0.0 Ok: queued as 6E1CF1681AB
>
>
> QUIT
>
> 221 2.0.0 Bye
> Connection closed by foreign host.
>```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
