---
id: IMAP-POP3
aliases:
  - IMAP-POP3
tags:
  - Networking/Services/IMAP-POP3/General
links: "[[Services]]"
ports:
  - 110
  - 143
  - 993
  - 995
---

# IMAP/POP3

Clients access these structures online and can create local copies,
resulting in a uniform database.

The client establishes the connection to the server via port `143`, using
text-based commands in `ASCII` format. Several commands can be sent in
succession without confirmation from the server. Later confirmations can be
assigned to the individual commands using identifiers.

<!-- IMAP {{{-->
## IMAP

**IMAP** ([Internet Message Access Protocol](https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol))
is a *client-server* protocol that allows synchronization and online management
of e-mails directly on a remote server, and supports folder structures.

**IMAP** works unencrypted by default (including credentials).
Many e-mail servers require establishing an encrypted **IMAP** session:
- **Port** `143`: Explicitly upgraded via [STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)
- **Port** `993`: Encrypted by default, using SSL/TLS

**IMAP** was designed to normally leave all messages on the server to permit
management with multiple client applications, and to support both *online* and
*offline* modes of operation.
<!-- }}} -->

<!-- POP3 {{{-->
## POP3

**POP3** ([Post Office Protocol](https://en.wikipedia.org/wiki/Post_Office_Protocol))
is used to list, retrieve, and delete e-mails from the server,
typically downloading them for offline use.

**POP3** works unencrypted by default (including credentials).
Many e-mail servers require establishing an encrypted **POP3** session:
- **Port** `110`: Explicitly upgraded via [STARTTLS](https://en.wikipedia.org/wiki/Post_Office_Protocol)
- **Port** `995`: Encrypted by default, using SSL/TLS

**POP3** clients have the option to leave e-mails on the server after retrieval
and only download new messages (identified by the UIDL command).
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

Both **IMAP** and **POP3** have a large number of configuration options, making
it difficult to deep dive into each component ([dovecot-imapd](https://packages.debian.org/sid/dovecot-imapd)
and [dovecot-pop3d](https://doc.dovecot.org/2.3/configuration_manual/protocols/pop3_server/))
in more detail.

<!-- Dangerous Settings {{{-->
### Dangerous Settings

Improper configuration could allow an attacker to obtain additional information
(e.g., *debugging executed commands*, *logging in as anonymous*, *etc*.)

<!-- Danger {{{-->
> [!danger]-
>
> **Dangerous Settings**
>
>| Setting                   | Description                   |
>| ------------------------- | ----------------------------- |
>| `auth_debug`              | Enables all authentication debug logging |
>| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged |
>| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons |
>| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated |
>| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism |
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->
