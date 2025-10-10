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

<!-- Internet Message Access Protocol {{{-->
## Internet Message Access Protocol

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

<!-- Post Office Protocol {{{-->
## Post Office Protocol

**POP3** ([Post Office Protocol](https://en.wikipedia.org/wiki/Post_Office_Protocol))
is used to list, retrieve, and delete e-mails from the server, typically
downloading them for offline use.

**POP3** works unencrypted by default (including credentials).
Many e-mail servers require establishing an encrypted **POP3** session:
- **Port** `110`: Explicitly upgraded via [STARTTLS](https://en.wikipedia.org/wiki/Post_Office_Protocol)
- **Port** `995`: Encrypted by default, using SSL/TLS

**POP3** clients have the option to leave e-mails on the server after retrieval
and only download new messages (identified by the UIDL command).
<!-- }}} -->

<!-- Default Configuration {{{-->
## Default Configuration

Both **IMAP** and **POP3** have a large number of configuration options, making
it difficult to deep dive into each component ([dovecot-imapd](https://packages.debian.org/sid/dovecot-imapd)
and [dovecot-pop3d](https://doc.dovecot.org/2.3/configuration_manual/protocols/pop3_server/))
in more detail.
<!-- }}} -->

<!-- IMAP Commands {{{-->
### IMAP Commands

> [!example]-
>
> **IMAP Commands**
>
>| Command                       | Description |
>| ----------------------------- | ------------------------------------ |
>| 1 LOGIN username password     | User's login |
>| 1 LIST "" *                   | Lists all directories |
>| 1 CREATE "INBOX"              | Creates a mailbox with a specified name |
>| 1 DELETE "INBOX"              | Deletes a mailbox |
>| 1 RENAME "ToRead" "Important" | Renames a mailbox |
>| 1 LSUB "" *                   | Returns a subset of names from the set of names that the User has declared as being active or subscribed |
>| 1 SELECT INBOX                | Selects a mailbox so that messages in the mailbox can be accessed |
>| 1 UNSELECT INBOX              | Exits the selected mailbox |
>| 1 FETCH <ID> all              | Retrieves data associated with a message in the mailbox |
>| 1 CLOSE                       | Removes all messages with the Deleted flag set |
>| 1 LOGOUT                      | Closes the connection with the IMAP server |
<!-- }}} -->

<!-- POP3 Commands {{{-->
### POP3 Commands

> [!example]-
>
> **POP3 Commands**
>
>| Command         | Description                        |
>| --------------- | ---------------------------------- |
>| `USER username` | Identifies the user                |
>| `PASS password` | Authentication of the user using its password |
>| `STAT`          | Requests the number of saved emails from the server |
>| `LIST`          | Requests from the server the number and size of all emails |
>| `RETR id`       | Requests the server to deliver the requested email by ID |
>| `DELE id`       | Requests the server to delete the requested email by ID |
>| `CAPA`          | Requests the server to display the server capabilities |
>| `RSET`          | Requests the server to reset the transmitted information |
>| `QUIT`          | Closes the connection with the POP3 server |
<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

Improper configuration could allow an attacker to obtain additional information
(e.g., *debugging executed commands*, *logging in as anonymous*, *etc*.)

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
