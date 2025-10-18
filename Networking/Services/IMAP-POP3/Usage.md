---
id: IMAP-POP3
tags:
  - Networking/Services/IMAP-POP3/Usage
links: "[[Services]]"
---

# Usage

## IMAP Connect

Connect and interact with an **IMAP** server using **openssl**
(*TLS Encrypted Interaction*)

```sh
openssl s_client -connect <target>:imaps
```

<!-- Exmaple {{{-->
> [!example]-
>
> ```sh
> openssl s_client -connect 10.129.14.128:imaps
> ```
> ```sh
> CONNECTED(00000003)
> Can't use SSL_get_servername
> depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
> verify error:num=18:self signed certificate
> verify return:1
> depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
> verify return:1
> ---
> Certificate chain
>  0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Customer Support, CN = mail1.inlanefreight.htb, emailAddress = cry0l1t3@inlanefreight.htb
>
> ...SNIP...
>
> ---
> read R BLOCK
> ---
> Post-Handshake New Session Ticket arrived:
> SSL-Session:
>     Protocol  : TLSv1.3
>     Cipher    : TLS_AES_256_GCM_SHA384
>     Session-ID: 2B7148CD1B7B92BA123E06E22831FCD3B365A5EA06B2CDEF1A5F397177130699
>     Session-ID-ctx:
>     Resumption PSK: 4D9F082C6660646C39135F9996DDA2C199C4F7E75D65FA5303F4A0B274D78CC5BD3416C8AF50B31A34EC022B619CC633
>     PSK identity: None
>     PSK identity hint: None
>     SRP username: None
>     TLS session ticket lifetime hint: 7200 (seconds)
>     TLS session ticket:
>     0000 - 68 3b b6 68 ff 85 95 7c-8a 8a 16 b2 97 1c 72 24   h;.h...|......r$
>     0010 - 62 a7 84 ff c3 24 ab 99-de 45 60 26 e7 04 4a 7d   b....$...E`&..J}
>     0020 - bc 6e 06 a0 ff f7 d7 41-b5 1b 49 9c 9f 36 40 8d   .n.....A..I..6@.
>     0030 - 93 35 ed d9 eb 1f 14 d7-a5 f6 3f c8 52 fb 9f 29   .5........?.R..)
>     0040 - 89 8d de e6 46 95 b3 32-48 80 19 bc 46 36 cb eb   ....F..2H...F6..
>     0050 - 35 79 54 4c 57 f8 ee 55-06 e3 59 7f 5e 64 85 b0   5yTLW..U..Y.^d..
>     0060 - f3 a4 8c a6 b6 47 e4 59-ee c9 ab 54 a4 ab 8c 01   .....G.Y...T....
>     0070 - 56 bb b9 bb 3b f6 96 74-16 c9 66 e2 6c 28 c6 12   V...;..t..f.l(..
>     0080 - 34 c7 63 6b ff 71 16 7f-91 69 dc 38 7a 47 46 ec   4.ck.q...i.8zGF.
>     0090 - 67 b7 a2 90 8b 31 58 a0-4f 57 30 6a b6 2e 3a 21   g....1X.OW0j..:!
>     00a0 - 54 c7 ba f0 a9 74 13 11-d5 d1 ec cc ea f9 54 7d   T....t........T}
>     00b0 - 46 a6 33 ed 5d 24 ed b0-20 63 43 d8 8f 14 4d 62   F.3.]$.. cC...Mb
> 
>     Start Time: 1632081604
>     Timeout   : 7200 (sec)
>     Verify return code: 18 (self signed certificate)
>     Extended master secret: no
>     Max Early Data: 0
> ---
> read R BLOCK
> * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] HTB-Academy IMAP4 v.0.21.4
> ```
<!-- }}} -->

<!-- IMAP Commands {{{-->
## IMAP Commands

**IMAP** command [references](https://donsutherland.org/crib/imap)
(*[RFC 3501](https://datatracker.ietf.org/doc/html/rfc3501)*)

<!-- Unauthenticated {{{-->
### Unauthenticated

<!-- CAPABILITY {{{-->
#### CAPABILITY

Query server capabilities

```sh
capability
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 CAPABILITY
> * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE
> a1 OK Capability completed (0.001 + 0.000 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- STARTTLS {{{-->
#### STARTTLS

Start encrypted session (*only if `STARTTLS` [[#CAPABILITY]] is available*)

```sh
starttls
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 STARTTLS
> a1 OK Begin TLS negotiation now.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- AUTHENTICATE {{{-->
#### AUTHENTICATE

Initiate a
[SASL](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer)
authentication

```sh
authenticate login
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- LOGIN {{{-->
#### LOGIN

Log in with credentials

```sh
login <user@domain.com> <password>
```

<!-- Example {{{-->
> [!example]-
>
> Log in as `robin`:`robin`
>
> ```sh
> a1 LOGIN robin robin
> a1 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Authenticated {{{-->
### Authenticated

<!-- LIST {{{-->
#### LIST

List all mailboxes/folders

```sh
LIST "" *
```

List a specific mailbox/folder

```sh
list "<mailbox>/" *
```

<!-- Example {{{-->
> [!example]-
>
> List all mailboxes/folders
>
> ```sh
> a1 LIST "" *
> * LIST (\Noselect \HasChildren) "." DEV
> * LIST (\Noselect \HasChildren) "." DEV.DEPARTMENT
> * LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT
> * LIST (\HasNoChildren) "." INBOX
> a1 OK List completed (0.001 + 0.000 secs).
> ```
>
> List specific mailbox/folder
>
> ```sh
> 1 list "INBOX/" *
> 1 OK List completed (0.001 + 0.000 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- STATUS {{{-->
#### STATUS

Request the status of the provided mailbox/folder

```sh
status <mailbox> (<option_1> <option_2> ...)
```

<!-- Options {{{-->
> [!info]- Options
>
> The client must advise the server what attributes of the folder
> that is interested in
>
> - `MESSAGES`: The number of messages in the mailbox
> - `RECENT`: The number of messages with the `\Recent` flag set
> - `UIDNEXT`: The next unique identifier value of the mailbox
> - `UIDVALIDITY`: The unique identifier validity value of the mailbox
> - `UNSEEN`: The number of messages which do not have the `\Seen` flag set
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Query the number of unseen messages in `DEV.DEPARTMENT.INT`
>
> ```sh
> 1 STATUS "DEV.DEPARTMENT.INT" (MESSAGES UNSEEN)
> * STATUS DEV.DEPARTMENT.INT (MESSAGES 1 UNSEEN 0)
> 1 OK Status completed (0.001 + 0.000 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- SELECT {{{-->
#### SELECT

Select a particular mailbox/folder

```sh
select "<mailbox>"
```

<!-- Example {{{-->
> [!example]-
>
> Select the mailbox/folder `DET.DEPARTMENT.INT`
>
> ```sh
> 1 select "DEV.DEPARTMENT.INT"
> * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
> * OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
> * 1 EXISTS
> * 0 RECENT
> * OK [UIDVALIDITY 1636414279] UIDs valid
> * OK [UIDNEXT 2] Predicted next UID
> 1 OK [READ-WRITE] Select completed (0.001 + 0.000 secs).
> ```
<!-- }}} -->

Examine a particular mailbox/folder (*Same as [[#SELECT]] but read-only*)

```sh
examine "<mailbox>"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 select "DEV.DEPARTMENT.INT"
> * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
> * OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
> * 1 EXISTS
> * 0 RECENT
> * OK [UIDVALIDITY 1636414279] UIDs valid
> * OK [UIDNEXT 2] Predicted next UID
> ```
> - The mailbox contains 1 message
<!-- }}} -->

The following commands become available once in
[[#SELECT|SELECT/EXAMINE]] mode

<!-- CHECK {{{-->
##### CHECK

Request the server to complete some housekeeping on the mailbox

```sh
check
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> A1 CHECK
> A1 OK CHECK Completed
> ```
<!-- }}} -->

<!-- }}} -->

<!-- CLOSE {{{-->
##### CLOSE

Close the currently selected mailbox and run [[#EXPUNGE]]

```sh
close
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 CLOSE
> a1 OK CLOSE completed
> ```
<!-- }}} -->

<!-- }}} -->

<!-- EXPUNGE {{{-->
##### EXPUNGE

Delete messages with the `\Deleted` flag set

```
expunge
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 expunge
> * 2 EXPUNGE
> OK Expunge completed.
> ```
<!-- }}} -->

<!-- }}} -->

<!-- SEARCH {{{-->
##### SEARCH

Search messages in the selected mailbox/folder

```sh
search <option>
```

<!-- Options {{{-->
> [!info]- Options
>
> **Possible search criteria**
>
> Multiple search terms considered `AND` by default
>
> - `ALL`: All messages in the mailbox
> - `ANSWERED`: Messages with the `\Answered` flag set
> - `BCC <string>`: Messages that contain the specified string in the envelope structure’s BCC field
> - `BEFORE <date>`: Messages whose internal date (disregarding time and timezone) is earlier than the specified date
> - `BODY <string>`: Messages that contain the specified string in the body of the message
> - `CC <string>`: Messages that contain the specified string in the envelope structure’s CC field
> - `DELETED`: Messages with the `\Deleted` flag set
> - `DRAFT`: Messages with the `\Draft` flag set
> - `FLAGGED`: Messages with the `\Flagged` flag set
> - `FROM <string>`: Messages that contain the specified string in the envelope structure’s FROM field
> - `HEADER <field-name> <string>`: Messages that have a header with the specified field-name and which contain the specified string in the text of the header (ie. what comes after the colon). If the string to search is zero-length, this matches all messages that have a header line with the specified field-name, regardless of the contents.
> - `KEYWORD <flag>`: Messages with the specified keyword flag set
> - `LARGER <n>`:  Messages with a size larger than the specified number of octets
> - `NEW`: Messages that have the `\Recent` flag set but not the `\Seen` flag
> - `NOT <search-key>`: Messages that do not match the specified search key
> - `OLD`: Messages that do not have the `\Recent` flag set
> - `ON <date>`: Messages whose internal date (disregarding time and timezone) is within the specified date
> - `OR <search-key1> <search-key2>`: Messages that match either search key
> - `RECENT`: Messages that have the `\Recent` flag set
> - `SEEN`: Messages that have the `\Seen` flag set
> - `SENTBEFORE <date>`: Messages whose Date: header (disregarding time and timezone) is earlier than the specified date
> - `SENTON <date>`: Messages whose Date: header (disregarding time and timezone) is within the specified date
> - `SENTSINCE <date>`: Messages whose Date: header (disregarding time and timezone) is within or later than the specified date
> - `SINCE <date>`: Messages whose internal date (disregarding time and timezone) is within or later than the specified date
> - `SMALLER <n>`: Messages with a size smaller than the specified number of octets
> - `SUBJECT <string>`: Messages that contain the specified string in the envelope structure’s SUBJECT field
> - `TEXT <string>`: Messages that contain the specified string in the header or body of the message
> - `TO <string>`: Messages that contain the specified string in the envelope structure’s TO field
> - `UID <sequence set>`: Messages with unique identifiers corresponding to the specified unique identifier set Sequence set ranges are permitted.
> - `UNANSWERED`: Messages that do not have the `\Answered` flag set
> - `UNDELETED`: Messages that do not have the `\Deleted` flag set
> - `UNDRAFT`: Messages that do not have the `\Draft` flag set
> - `UNFLAGGED`: Messages that do not have the `\Flagged` flag set
> - `UNKEYWORD <flag>`: Messages that do not have the specified keyword flag set
> - `UNSEEN`: Messages that do not have the `\Seen` flag set
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Search all mails in the selected mailbox by [[#UID]]
>
> ```sh
> s1 uid search all
> * SEARCH 1
> s1 OK Search completed (0.001 + 0.000 secs)
> ```
<!-- }}} -->

<!-- }}} -->

<!-- FETCH {{{-->
##### FETCH

Fetch messages from the selected mailbox/folder

```sh
fetch (<option>)
```

<!-- Options {{{-->
> [!info]- Options
>
> **Possible search criteria**
>
> - `ALL`: Macro equivalent to: (`FLAGS INTERNALDATE RFC822.SIZE ENVELOPE`)
> - `FAST`: Macro equivalent to: (`FLAGS INTERNALDATE RFC822.SIZE`)
> - `FULL`: Macro equivalent to: (`FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY`)
> - `BODY`: Non-extensible form of `BODYSTRUCTURE`.
> - `BODY[<section>]<<partial>>`: The text of a particular body section. The section specification is a set of zero or more part specifiers delimited by periods. A part specifier is either a part number or one of the following: HEADER, HEADER.FIELDS, HEADER.FIELDS.NOT, MIME, and TEXT. An empty section specification refers to the entire message, including the header. You may even select only parts of a multipart MIME message and even specific octets within that part, see RFC 3501#section-6.4.5 for more details.
> - `BODY.PEEK[<section>]<<partial>>`: An alternate form of BODY[<section>] that does not implicitly set the \Seen flag.
> - `BODYSTRUCTURE`: The MIME body structure of the message. This is computed by the server by parsing the MIME header fields in the header and body MIME headers.
> - `ENVELOPE`: The envelope structure of the message. This is computed by the server by parsing the message header into the component parts, defaulting various fields as necessary.
> - `FLAGS`: The flags that are set for this message.
> - `INTERNALDATE`: The internal date of the message.
> - `RFC822`: Functionally equivalent to BODY[], differing in the syntax of the resulting untagged FETCH data in that the full RFC822 message is returned.
> - `RFC822.HEADER`: Functionally equivalent to BODY.PEEK[HEADER], with RFC822 header syntax returned.
> - `RFC822.SIZE`: The size of the message.
> - `RFC822.TEXT`: Functionally equivalent to BODY[TEXT], differing in the syntax of the resulting untagged FETCH data as RFC822.TEXT is returned.
> - `UID`: The unique identifier for the message.
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Fetch message by [[UID]]
>
> ```sh
> A1 UID FETCH 1 (UID RFC822.SIZE BODY.PEEK[])
> * 1 FETCH (UID 1 RFC822.SIZE 167 BODY[] {167}
> Subject: Flag
> To: Robin <robin@inlanefreight.htb>
> From: CTO <devadmin@inlanefreight.htb>
> Date: Wed, 03 Nov 2021 16:13:27 +0200
>
> HTB{983uzn8jmfgpd8jmof8c34n7zio}
> )
> A1 OK Fetch completed (0.004 + 0.000 + 0.003 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- COPY {{{-->
##### COPY

Copy a message from the currently selected folder to a different folder

```sh
copy <id> "<destination_folder>"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> c1 COPY 10 "work.due today"
> c1 OK [COPYUID 1548379804 17 1] Copy completed (0.007 + 0.000 + 0.006 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- UID {{{-->
##### UID

UID instructs the server to use UIDs as arguments or results
(*rather than message sequence numbers, as is the default*)

UID is a modifier command
(e.g., [[#COPY|COPY]], [[#FETCH|FETCH]], [[#SEARCH|SEARCH]])

<!-- Example {{{-->
> [!example]-
>
> ```sh
> A1 UID FETCH 1 (UID RFC822.SIZE BODY.PEEK[])
> * FLAGS (\Answered \Flagged \Deleted \Seen \Draft some-flag a-different-flag a-funny-flag)
> * OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft some-flag a-different-flag a-funny-flag \*)] Flags permitted.
> * 3 FETCH (UID 10 FLAGS (a-funny-flag))
> w OK Store completed (0.004 + 0.000 + 0.003 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Subscribe Operations {{{-->
#### Subscribe Operations

<!-- SUBSCRIBE {{{-->
##### SUBSCRIBE

Subscribe to a set of mailboxes/folders to be notified of updates

```sh
subscribe <mailbox>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 SUBSCRIBE #news.comp.mail.mime
> a1 OK SUBSCRIBE completed
> ```
<!-- }}} -->

<!-- }}} -->

<!-- UNSUBSCRIBE {{{-->
##### UNSUBSCRIBE

Unsubscribe from the specified mailbox/folder


```sh
unsubscribe <mailbox>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 UNSUBSCRIBE #news.comp.mail.mime
> a1 OK UNSUBSCRIBE completed
> ```
<!-- }}} -->

<!-- }}} -->

<!-- LSUB {{{-->
##### LSUB

[[#LIST|LIST]], but only return subscribed mailboxes

```sh
a1 lsub "#news." "comp.mail.*"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
>
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Directory Operations {{{-->
#### Directory Operations

<!-- CREATE {{{-->
##### CREATE

Create new folder

```sh
create <folder>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> c CREATE work
> c OK Create completed (0.002 + 0.000 + 0.001 secs).
> k2 LIST "" "*"
> * LIST (\HasNoChildren \Trash) "." Trash
> * LIST (\HasNoChildren) "." folder1
> * LIST (\HasNoChildren) "." work
> * LIST (\HasNoChildren) "." INBOX
> k2 OK List completed (0.001 + 0.000 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- DELETE {{{-->
##### DELETE

Delete a folder

```sh
delete <folder>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> A683 DELETE blurdybloop
> A683 OK DELETE completed
> ```
<!-- }}} -->

<!-- }}} -->

<!-- RENAME {{{-->
##### RENAME

Rename a folder

```sh
rename <folder_old> <folder_new>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 RENAME blurdybloop sarasoop
> a1 OK RENAME completed
> ```
<!-- }}} -->

<!-- }}} -->

##### APPEND

Append a message to the specified mailbox

<!-- Example {{{-->
> [!example]-
>
> ```sh
> a1 APPEND "work.due today" {89}
> + OK
> Subject: Send the weekly report
>
> Remember to send the weekly report to THE BOSS TODAY!!
> a1 OK [APPENDUID 1548379804 2] Append completed (0.007 + 4.391 + 0.005 secs).
> ```
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->

<!-- POP3 Commands {{{-->
## POP3 Commands

<!-- Example {{{-->
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
>| `CAPA`          | Show server capabilities |
>| `RSET`          | Requests the server to reset the transmitted information |
>| `QUIT`          | Closes the connection with the POP3 server |
<!-- }}} -->

___

<!-- }}} -->
