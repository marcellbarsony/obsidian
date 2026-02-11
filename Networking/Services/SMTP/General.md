---
id: General
aliases: []
tags:
  - Networking/Services/SMTP/General
links: "[[Networking/Services/General]]"
port:
  - 25
  - 465
  - 587
---

# SMTP

**SMTP** ([Simple Mail Transfer Protocol](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol))
is a TCP/IP protocol for sending e-mails

**SMTP** in principle is a *client-server*-based protocol, and it can be used
between an e-mail client and an outgoing mail server or between two **SMTP**
servers

**SMTP** is often combined with
[[IMAP-POP3/General|IMAP/POP3]], due to its limitations in
queuing messages on the recipient's end

<!-- Resources {{{-->
> [!info]- Resources
>
> - [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)
> - [Hackviser](https://hackviser.com/tactics/pentesting/services/smtp#enumeration)
>
<!-- }}} -->

___

<!-- Ports {{{-->
## Ports

**SMTP** servers accept connection requests on
- **TCP port** `25`: Typically unencrypted connection (or may use `STARTTLS` to
  upgrade connection)
- **TCP port** `465`: Used for SMTP over implicit TLS; the connection is
  encrypted from the start (no `STARTTLS`)
- **TCP port** `587`: `STARTTLS` command is sent to switch the existing
  plaintext connection to encrypted. The client should confirm its identity by
  providing a username and password.

___
<!-- }}} -->

<!-- Operation {{{-->
## Operation

Modern **SMTP** servers support the protocol extension [ESMTP](https://www.geeksforgeeks.org/computer-networks/what-is-esmtp-extended-simple-mail-transfer-protocol/)
with [SMTP-Auth](https://en.wikipedia.org/wiki/SMTP_Authentication) to prevent
spam using authentication mechanisms that allow only authorized users to send
e-mails

- **SMTP Client**, (a.k.a. **E-mail Client** or **Mail User Agent** ([MUA](https://en.wikipedia.org/wiki/Email_client))),
  composes the e-mail (with headers and body *as per [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322)*)
  and submits it to the **SMTP Server** via port `587`

- **Mail Submission Agent** ([MSA](https://en.wikipedia.org/wiki/Message_submission_agent))
  (*optional*) authenticates the sender and checks policy before passing the
  mail to the **Mail Transfer Agent** [MTA](https://en.wikipedia.org/wiki/Message_transfer_agent)

- The **SMTP Server** (running a **Mail Transfer Agent** ([MTA](https://en.wikipedia.org/wiki/Message_transfer_agent))),
  is the software responsible for sending and receiving e-mails:
    - Applies policies (spam check, size limits, etc.)
    - Looks up the **DNS MX Record** for the recipient's domain to find the
      destination e-mail server
    - Sends the e-mail to the destination **Mail Transfer Agent** ([MTA](https://en.wikipedia.org/wiki/Message_transfer_agent))

- The **destination MTA** (on the recipient's **SMTP Server**) receives the
  e-mail message and processes it for delivery

- The **Mail Delivery Agent** ([MDA](https://en.wikipedia.org/wiki/Message_delivery_agent))
  transfers it to the recipient's mailbox (via [[Networking/Services/IMAP-POP3/General|IMAP/POP3]])

<!-- Info {{{-->
> [!info]-
>
> E-mail Client ([MUA](https://en.wikipedia.org/wiki/Email_client))
> ➞ Submission Agent ([MSA](https://en.wikipedia.org/wiki/Message_submission_agent))
> ➞ Open Relay ([MTA](https://en.wikipedia.org/wiki/Open_mail_relay))
> ➞ Mail Delivery Agent ([MDA](https://en.wikipedia.org/wiki/Message_delivery_agent))
> ➞ Mailbox (POP3/IMAP)
>
> ![[process.png]]
>
<!-- }}} -->

___
<!-- }}} -->

<!-- Disadvantages {{{-->
## Disadvantages

**SMTP** has two disadvantages inherent to the network protocol:

1. **Sending an e-mail using **SMTP** does not return a usable delivery
   confirmation**:<br>
   Its formatting is not specified by default, so that usually an
   English-language error message (including the sent mail's header) is returned

2. **Users are not authenticated when the connection is established,
   and the sender of an e-mail therefore is unreliable**:<br>
   **SMTP** relays are often misused to send spam,
   and the originators usually use arbitrary fake sender
   addresses (*mail spoofing*). To authenticate senders, DomainKeys
   ([DKIM](https://dkim.org/)) and the Sender Policy Framework
   ([SPF](https://dmarcian.com/what-is-spf/)) can be used.

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Default Configuration {{{-->
### Default Configuration

The default configuration is usually located at `/etc/postfix/main.cf`

```sh
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
> ```
>
> ```sh
> smtpd_banner = ESMTP Server 
> biff = no
> append_dot_mydomain = no
> readme_directory = no
> compatibility_level = 2
> smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
> myhostname = mail1.inlanefreight.htb
> alias_maps = hash:/etc/aliases
> alias_database = hash:/etc/aliases
> smtp_generic_maps = hash:/etc/postfix/generic
> mydestination = $myhostname, localhost 
> masquerade_domains = $myhostname
> mynetworks = 127.0.0.0/8 10.129.0.0/16
> mailbox_size_limit = 0
> recipient_delimiter = +
> smtp_bind_address = 0.0.0.0
> inet_protocols = ipv4
> smtpd_helo_restrictions = reject_invalid_hostname
> home_mailbox = /home/postfix
> ```
<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

To prevent the sent e-mails from being filtered by spam filters,
the sender can use a relay server that the recipient trusts.
The sender must authenticate himself to the relay server before using it.

<!-- Open Relay Configuration {{{-->
#### Open Relay Configuration

The **SMTP Server** can send fake e-mails
([[Networking/Services/SMTP/Exploitation#Open Relay Attack|Open Relay Attack]])
and thus initialize communication between multiple parties

<!-- Danger {{{-->
> [!danger]
>
> Allow connections from any IP address
>
> ```sh
> mynetworks = 0.0.0.0/0
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
